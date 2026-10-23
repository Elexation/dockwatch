package inventory

import "testing"

func TestRef(t *testing.T) {
	for in, want := range map[string]string{
		"nginx":                          "nginx:latest",
		"nginx:latest":                   "nginx:latest",
		"docker.io/library/nginx:latest": "nginx:latest",
		"index.docker.io/library/nginx":  "nginx:latest",
		"gitea/gitea:1.24":               "gitea/gitea:1.24",
		"docker.io/gitea/gitea:1.24":     "gitea/gitea:1.24",
		"ghcr.io/owner/app":              "ghcr.io/owner/app:latest",
		"localhost:5000/app:dev":         "localhost:5000/app:dev",
		"nginx@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef":                            "nginx@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"cloudflare/cloudflared:2026.10.3@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": "cloudflare/cloudflared:2026.10.3",
		"docker.io/library/nginx:1.27@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef":     "nginx:1.27",
		"localhost:5000/app:dev@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef":           "localhost:5000/app:dev",
		"localhost:5000/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef":               "localhost:5000/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"Not A Ref": "Not A Ref",
	} {
		if got := Ref(in); got != want {
			t.Errorf("Ref(%q) = %q, want %q", in, got, want)
		}
	}
}
