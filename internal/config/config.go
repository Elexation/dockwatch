// Package config reads and validates DockWatch configuration from the
// environment. Every DW_* variable is parsed up front; invalid values are
// fatal (fail-fast), unknown DW_* variables are warned about but tolerated.
package config

import (
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
	Name string // operator-invented <NAME>, lowercased; the agent's name everywhere
	URL  string // https://host:port
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
	RequireHTTPS bool
	ResetAdmin   bool
}

func (c *Config) IsHub() bool   { return c.Mode == "hub" }
func (c *Config) IsAgent() bool { return c.Mode == "agent" }

var agentKeyRe = regexp.MustCompile(`^DW_AGENT_(.+)_URL$`)

var knownKeys = map[string]bool{
	"DW_MODE": true, "DW_PORT": true, "DW_DATA": true, "DW_CERTS": true,
	"DW_DOCKER_SOCK": true, "DW_LOCAL_NAME": true, "DW_INTERVAL": true,
	"DW_NTFY_URL": true, "DW_NTFY_TOPIC": true, "DW_NTFY_TOKEN": true,
	"DW_HTTPS": true, "DW_TLS_CERT": true, "DW_TLS_KEY": true, "DW_DOMAIN": true,
	"DW_TRUSTED_PROXY": true, "DW_REQUIRE_HTTPS": true, "DW_RESET_ADMIN": true,
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
	requireHTTPS, err := parseBool(env, "DW_REQUIRE_HTTPS", false)
	if err != nil {
		return nil, nil, err
	}
	resetAdmin, err := parseBool(env, "DW_RESET_ADMIN", false)
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

		HTTPS: https,
		// DW_TLS_CERT/DW_TLS_KEY both-or-neither cross-check is deferred to the
		// Phase 4 web transport, where the listener that consumes them is built.
		TLSCert:      env["DW_TLS_CERT"],
		TLSKey:       env["DW_TLS_KEY"],
		Domain:       domain,
		TrustedProxy: trustedProxy,
		RequireHTTPS: requireHTTPS,
		ResetAdmin:   resetAdmin,
	}

	return cfg, warnings(env, cfg), nil
}

func warnings(env map[string]string, cfg *Config) []string {
	var out []string
	if cfg.IsHub() && cfg.NtfyTopic == "" {
		out = append(out, "DW_NTFY_TOPIC not set: notifications disabled")
	}

	var unknown []string
	for k := range env {
		if strings.HasPrefix(k, "DW_") && !knownKeys[k] && !agentKeyRe.MatchString(k) {
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
		agents = append(agents, Agent{Name: name, URL: v})
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].Name < agents[j].Name })
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
