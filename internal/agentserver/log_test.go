package agentserver

import "testing"

func TestIsHealthProbe(t *testing.T) {
	for line, want := range map[string]bool{
		"http: TLS handshake error from 127.0.0.1:58653: EOF":                    true,
		"http: TLS handshake error from [::1]:58653: EOF":                        true,
		"http: TLS handshake error from 192.0.2.5:58653: EOF":                    false,
		"http: TLS handshake error from 127.0.0.1:58653: tls: bad certificate":   false,
		"http: TLS handshake error from 127.0.0.1:58653: read: connection reset": false,
	} {
		if got := isHealthProbe(line); got != want {
			t.Errorf("isHealthProbe(%q) = %v, want %v", line, got, want)
		}
	}
}
