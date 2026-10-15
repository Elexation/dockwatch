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
		"nginx@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": "nginx@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"Not A Ref": "Not A Ref",
	} {
		if got := Ref(in); got != want {
			t.Errorf("Ref(%q) = %q, want %q", in, got, want)
		}
	}
}
