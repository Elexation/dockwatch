package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, warns, err := Load(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IsHub() || cfg.Mode != "hub" {
		t.Errorf("Mode = %q, want hub", cfg.Mode)
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Port)
	}
	if cfg.Interval != time.Hour {
		t.Errorf("Interval = %s, want 1h", cfg.Interval)
	}
	if cfg.NtfyURL != "https://ntfy.sh" {
		t.Errorf("NtfyURL = %q", cfg.NtfyURL)
	}
	if cfg.DataDir != "/data" || cfg.CertsDir != "/certs" || cfg.DockerSock != "/var/run/docker.sock" {
		t.Errorf("dirs = %q %q %q", cfg.DataDir, cfg.CertsDir, cfg.DockerSock)
	}
	if cfg.LocalName != "local" {
		t.Errorf("LocalName = %q", cfg.LocalName)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "DW_NTFY_TOPIC") {
		t.Errorf("warnings = %v, want notify-disabled warning", warns)
	}
}

func TestAgentModeDefaultPort(t *testing.T) {
	cfg, _, err := Load([]string{"DW_MODE=agent"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !cfg.IsAgent() || cfg.Port != 7443 {
		t.Errorf("agent mode: IsAgent=%v Port=%d", cfg.IsAgent(), cfg.Port)
	}
}

func TestAgents(t *testing.T) {
	cfg, _, err := Load([]string{
		"DW_NTFY_TOPIC=x",
		"DW_AGENT_HOME_URL=https://10.27.27.8:7443",
		"DW_AGENT_NAS_URL=https://nas.lan:7443",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(cfg.Agents) != 2 {
		t.Fatalf("agents = %d, want 2", len(cfg.Agents))
	}
	if cfg.Agents[0].Name != "home" || cfg.Agents[1].Name != "nas" {
		t.Errorf("agent names = %q %q, want home/nas (sorted, lowercased)", cfg.Agents[0].Name, cfg.Agents[1].Name)
	}
	if cfg.Agents[0].URL != "https://10.27.27.8:7443" {
		t.Errorf("home url = %q", cfg.Agents[0].URL)
	}
}

func TestFailFast(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"bad mode", []string{"DW_MODE=worker"}, "DW_MODE"},
		{"port zero", []string{"DW_PORT=0"}, "DW_PORT"},
		{"port high", []string{"DW_PORT=70000"}, "DW_PORT"},
		{"port nan", []string{"DW_PORT=abc"}, "DW_PORT"},
		{"interval floor", []string{"DW_INTERVAL=1s"}, "DW_INTERVAL"},
		{"interval bad", []string{"DW_INTERVAL=nope"}, "DW_INTERVAL"},
		{"agent plaintext", []string{"DW_AGENT_X_URL=http://h:1"}, "DW_AGENT_X_URL"},
		{"agent no port", []string{"DW_AGENT_X_URL=https://h"}, "DW_AGENT_X_URL"},
		{"agent with path", []string{"DW_AGENT_X_URL=https://h:1/x"}, "DW_AGENT_X_URL"},
		{"domain scheme", []string{"DW_DOMAIN=https://x.com"}, "DW_DOMAIN"},
		{"domain port", []string{"DW_DOMAIN=x.com:8080"}, "DW_DOMAIN"},
		{"bad bool", []string{"DW_HTTPS=maybe"}, "DW_HTTPS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Load(tc.env)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

func TestValidOverrides(t *testing.T) {
	cfg, _, err := Load([]string{
		"DW_INTERVAL=30m",
		"DW_PORT=9000",
		"DW_DOMAIN=updates.example.com",
		"DW_HTTPS=true",
		"DW_NTFY_TOPIC=t",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if cfg.Interval != 30*time.Minute {
		t.Errorf("interval = %s", cfg.Interval)
	}
	if cfg.Port != 9000 {
		t.Errorf("port = %d", cfg.Port)
	}
	if cfg.Domain != "updates.example.com" {
		t.Errorf("domain = %q", cfg.Domain)
	}
	if !cfg.HTTPS {
		t.Errorf("https = false, want true")
	}
}

func TestUnknownVarWarns(t *testing.T) {
	_, warns, err := Load([]string{"DW_NTFY_TOPIC=t", "DW_INTERVUL=2h"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	var found bool
	for _, w := range warns {
		if strings.Contains(w, "DW_INTERVUL") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %v, want DW_INTERVUL warning", warns)
	}
}
