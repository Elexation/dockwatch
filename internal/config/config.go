// Package config reads and validates DockWatch configuration from the
// environment. Every DW_* variable is parsed up front; invalid values are
// fatal (fail-fast), unknown DW_* variables are warned about but tolerated.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const intervalFloor = 5 * time.Minute

// Agent is one hub-configured agent, derived from a DW_AGENT_<NAME>_URL var.
type Agent struct {
	Name      string // operator-invented <NAME>, lowercased; the agent's name everywhere
	URL       string // https://host:port
	DownAlert bool   // DW_AGENT_<NAME>_DOWN_ALERT, default true; false for a host that is not always on
}

// Config is the fully parsed, validated DockWatch configuration.
type Config struct {
	Mode       string // "hub" | "agent"
	Port       int
	DataDir    string
	CertsDir   string
	DockerSock string
	LocalName  string
	Agents     []Agent

	Interval  time.Duration
	NtfyURL   string
	NtfyTopic string
	NtfyToken string

	HTTPS        bool
	TLSCert      string
	TLSKey       string
	Domain       string
	TrustedProxy bool
	ResetAdmin   bool

	APITokenSHA256 []byte // decoded DW_API_TOKEN_SHA256; nil leaves the API unregistered
}

// IsHub reports whether this process runs the hub role.
func (c *Config) IsHub() bool { return c.Mode == "hub" }

// IsAgent reports whether this process runs the agent role.
func (c *Config) IsAgent() bool { return c.Mode == "agent" }

var (
	agentKeyRe       = regexp.MustCompile(`^DW_AGENT_(.+)_URL$`)
	agentDownAlertRe = regexp.MustCompile(`^DW_AGENT_(.+)_DOWN_ALERT$`)
	ntfyTopicRe      = regexp.MustCompile(`^[-_A-Za-z0-9]{1,64}$`) // ntfy's documented topic rule
)

var knownKeys = map[string]bool{
	"DW_MODE": true, "DW_PORT": true, "DW_DATA": true, "DW_CERTS": true,
	"DW_DOCKER_SOCK": true, "DW_LOCAL_NAME": true, "DW_INTERVAL": true,
	"DW_NTFY_URL": true, "DW_NTFY_TOPIC": true, "DW_NTFY_TOKEN": true,
	"DW_HTTPS": true, "DW_TLS_CERT": true, "DW_TLS_KEY": true, "DW_DOMAIN": true,
	"DW_TRUSTED_PROXY": true, "DW_RESET_ADMIN": true, "DW_API_TOKEN_SHA256": true,
}

// Load parses environ (entries of the form "KEY=value", as from os.Environ)
// into a validated Config. The returned warnings are non-fatal advisories the
// caller should log. A non-nil error is fatal and means startup must abort.
func Load(environ []string) (*Config, []string, error) {
	env := make(map[string]string, len(environ))
	for _, kv := range environ {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			env[kv[:i]] = kv[i+1:]
		}
	}

	mode := orDefault(env, "DW_MODE", "hub")
	if mode != "hub" && mode != "agent" {
		return nil, nil, fmt.Errorf("invalid DW_MODE %q: must be \"hub\" or \"agent\"", mode)
	}

	defPort := 8080
	if mode == "agent" {
		defPort = 7443
	}
	port, err := parsePort(env["DW_PORT"], defPort)
	if err != nil {
		return nil, nil, err
	}

	interval, err := parseInterval(env["DW_INTERVAL"])
	if err != nil {
		return nil, nil, err
	}

	domain, err := parseDomain(env["DW_DOMAIN"])
	if err != nil {
		return nil, nil, err
	}

	https, err := parseBool(env, "DW_HTTPS", false)
	if err != nil {
		return nil, nil, err
	}
	trustedProxy, err := parseBool(env, "DW_TRUSTED_PROXY", false)
	if err != nil {
		return nil, nil, err
	}
	resetAdmin, err := parseBool(env, "DW_RESET_ADMIN", false)
	if err != nil {
		return nil, nil, err
	}
	apiHash, err := parseTokenHash(env["DW_API_TOKEN_SHA256"])
	if err != nil {
		return nil, nil, err
	}

	agents, err := parseAgents(env)
	if err != nil {
		return nil, nil, err
	}

	cfg := &Config{
		Mode:       mode,
		Port:       port,
		DataDir:    orDefault(env, "DW_DATA", "/data"),
		CertsDir:   orDefault(env, "DW_CERTS", "/certs"),
		DockerSock: orDefault(env, "DW_DOCKER_SOCK", "/var/run/docker.sock"),
		LocalName:  orDefault(env, "DW_LOCAL_NAME", "local"),
		Agents:     agents,

		Interval:  interval,
		NtfyURL:   orDefault(env, "DW_NTFY_URL", "https://ntfy.sh"),
		NtfyTopic: env["DW_NTFY_TOPIC"],
		NtfyToken: env["DW_NTFY_TOKEN"],

		HTTPS:        https,
		TLSCert:      env["DW_TLS_CERT"],
		TLSKey:       env["DW_TLS_KEY"],
		Domain:       domain,
		TrustedProxy: trustedProxy,
		ResetAdmin:   resetAdmin,

		APITokenSHA256: apiHash,
	}

	// Cross-checks; hub-only, as the agent ignores these vars.
	if cfg.IsHub() {
		if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
			return nil, nil, fmt.Errorf("DW_TLS_CERT and DW_TLS_KEY must both be set or both be unset")
		}
		// Otherwise the cert is silently ignored and login is served over plain HTTP.
		if cfg.TLSCert != "" && !cfg.HTTPS {
			return nil, nil, fmt.Errorf("DW_TLS_CERT and DW_TLS_KEY are set but DW_HTTPS is not true: set DW_HTTPS=true to serve them")
		}
		if err := checkNtfy(cfg.NtfyURL, cfg.NtfyTopic); err != nil {
			return nil, nil, err
		}
		// Hosts are keyed by name, so a clash would merge the two hosts' rows.
		for _, a := range cfg.Agents {
			if a.Name == cfg.LocalName {
				return nil, nil, fmt.Errorf("agent name %q is also DW_LOCAL_NAME: rename the agent or set a different DW_LOCAL_NAME", a.Name)
			}
		}
	}

	return cfg, warnings(env, cfg), nil
}

// checkNtfy rejects an ntfy base URL or topic that would only fail at publish
// time. Credentials belong in DW_NTFY_TOKEN, so a URL carrying them is refused,
// and errors never echo a password.
func checkNtfy(base, topic string) error {
	const want = "must be http(s)://host[:port][/path]"
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("invalid DW_NTFY_URL: %s", want) // url.Error would echo the raw value
	}
	if u.User != nil {
		return fmt.Errorf("invalid DW_NTFY_URL %q: put credentials in DW_NTFY_TOKEN, not the URL", u.Redacted())
	}
	// An empty "?" or "#" still moves the topic out of the path at publish time.
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" ||
		u.RawQuery != "" || u.ForceQuery || strings.Contains(base, "#") {
		return fmt.Errorf("invalid DW_NTFY_URL %q: %s", base, want)
	}
	if topic != "" && !ntfyTopicRe.MatchString(topic) {
		return fmt.Errorf("invalid DW_NTFY_TOPIC %q: must be the bare topic name, 1-64 letters, digits, '-' or '_'", topic)
	}
	return nil
}

func warnings(env map[string]string, cfg *Config) []string {
	var out []string
	if cfg.IsHub() && cfg.NtfyTopic == "" {
		out = append(out, "DW_NTFY_TOPIC not set: notifications disabled")
	}
	if cfg.IsHub() && cfg.NtfyToken != "" {
		// The parsed scheme, since url.Parse lowercases it: "HTTP://" is plaintext too.
		if u, err := url.Parse(cfg.NtfyURL); err == nil && u.Scheme == "http" {
			out = append(out, "DW_NTFY_TOKEN is sent unencrypted: DW_NTFY_URL uses http://")
		}
	}
	if cfg.IsHub() && cfg.APITokenSHA256 != nil && !cfg.HTTPS && !cfg.TrustedProxy {
		out = append(out, "the API token is sent unencrypted: DW_API_TOKEN_SHA256 is set but neither DW_HTTPS nor DW_TRUSTED_PROXY is")
	}

	var unknown []string
	for k := range env {
		if strings.HasPrefix(k, "DW_") && !knownKeys[k] && !agentKeyRe.MatchString(k) && !agentDownAlertRe.MatchString(k) {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)
	for _, k := range unknown {
		out = append(out, fmt.Sprintf("unknown environment variable %s (ignored)", k))
	}
	return out
}

func parseAgents(env map[string]string) ([]Agent, error) {
	var agents []Agent
	seen := make(map[string]string)
	for k, v := range env {
		m := agentKeyRe.FindStringSubmatch(k)
		if m == nil {
			continue
		}
		name := strings.ToLower(m[1])
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" ||
			u.Port() == "" || u.Path != "" || u.RawQuery != "" || u.User != nil {
			return nil, fmt.Errorf("invalid %s %q: must be https://host:port", k, v)
		}
		if p, err := strconv.Atoi(u.Port()); err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid %s %q: port must be 1-65535", k, v)
		}
		if prev, dup := seen[name]; dup {
			return nil, fmt.Errorf("duplicate agent name %q from %s and %s", name, prev, k)
		}
		seen[name] = k
		agents = append(agents, Agent{Name: name, URL: v, DownAlert: true})
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].Name < agents[j].Name })

	byName := make(map[string]int, len(agents))
	for i, a := range agents {
		byName[a.Name] = i
	}
	seenAlert := make(map[string]string)
	for k := range env {
		m := agentDownAlertRe.FindStringSubmatch(k)
		if m == nil {
			continue
		}
		name := strings.ToLower(m[1])
		i, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("%s set but no DW_AGENT_%s_URL configures agent %q", k, m[1], name)
		}
		if prev, dup := seenAlert[name]; dup {
			return nil, fmt.Errorf("duplicate down-alert setting for agent %q from %s and %s", name, prev, k)
		}
		seenAlert[name] = k
		on, err := parseBool(env, k, true)
		if err != nil {
			return nil, err
		}
		agents[i].DownAlert = on
	}
	return agents, nil
}

func parsePort(v string, def int) (int, error) {
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid DW_PORT %q: must be 1-65535", v)
	}
	return n, nil
}

func parseInterval(v string) (time.Duration, error) {
	if v == "" {
		return time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("invalid DW_INTERVAL %q: %v", v, err)
	}
	if d < intervalFloor {
		return 0, fmt.Errorf("invalid DW_INTERVAL %q: must be >= %s", v, intervalFloor)
	}
	return d, nil
}

func parseDomain(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if strings.Contains(v, "://") || strings.ContainsAny(v, "/:") {
		return "", fmt.Errorf("invalid DW_DOMAIN %q: must be a bare hostname (no scheme, slash, or port)", v)
	}
	for _, r := range v {
		if r != '-' && r != '.' && !(r >= 'a' && r <= 'z') &&
			!(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') {
			return "", fmt.Errorf("invalid DW_DOMAIN %q: invalid hostname character %q", v, r)
		}
	}
	return v, nil
}

// parseTokenHash decodes the API token's hex SHA-256; nil if unset. The error
// never echoes the value, which may be the token itself pasted by mistake.
func parseTokenHash(v string) ([]byte, error) {
	if v == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != sha256.Size {
		return nil, errors.New(`invalid DW_API_TOKEN_SHA256: must be the token's SHA-256 as 64 hex characters (printf '%s' "$TOKEN" | sha256sum)`)
	}
	return b, nil
}

func parseBool(env map[string]string, key string, def bool) (bool, error) {
	v, ok := env[key]
	if !ok || v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("invalid %s %q: must be true or false", key, v)
	}
	return b, nil
}

func orDefault(env map[string]string, key, def string) string {
	if v, ok := env[key]; ok && v != "" {
		return v
	}
	return def
}
