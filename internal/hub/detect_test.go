package hub

import (
	"context"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/registry"
	"github.com/elexation/dockwatch/internal/store"
)

type fakeReg struct {
	tags    map[string][]string
	digests map[string]string
	tagsErr error
	digErr  error
	listN   int
	digN    int
}

func (f *fakeReg) ListTags(_ context.Context, repo string) ([]string, error) {
	f.listN++
	if f.tagsErr != nil {
		return nil, f.tagsErr
	}
	return f.tags[repo], nil
}

func (f *fakeReg) Digest(_ context.Context, ref string) (string, error) {
	f.digN++
	if f.digErr != nil {
		return "", f.digErr
	}
	return f.digests[ref], nil
}

func container(image string, digested bool) inventory.Container {
	c := inventory.Container{Image: image, State: "running"}
	if digested {
		c.RepoDigests = []string{"repo@sha256:local"}
	}
	return c
}

func TestClassify(t *testing.T) {
	cases := []struct {
		image    string
		digested bool
		want     Kind
	}{
		{"myapp:1.0", false, KindLocal}, // no repo digests => locally built
		{"gitea/gitea:1.24.3", true, KindSemver},
		{"app:v1.2.3", true, KindSemver},
		{"nginx:latest", true, KindDigest},
		{"nginx", true, KindDigest}, // missing tag defaults to latest
		{"redis:stable", true, KindDigest},
	}
	for _, tc := range cases {
		if got := Classify(container(tc.image, tc.digested)); got != tc.want {
			t.Errorf("Classify(%q, digested=%v) = %v, want %v", tc.image, tc.digested, got, tc.want)
		}
	}
}

func TestSchemeOf(t *testing.T) {
	same := [][2]string{
		{"1.24.3", "1.25.0"},
		{"1.24.3-alpine", "1.25.0-alpine"},
		{"1.24.3-ls45", "1.25.0-ls123"}, // trailing digit runs collapse
		{"v1.2.3", "v1.3.0"},
		{"1.2", "1.3"},
	}
	for _, p := range same {
		if schemeOf(p[0]) != schemeOf(p[1]) {
			t.Errorf("schemeOf(%q)=%q != schemeOf(%q)=%q, want same", p[0], schemeOf(p[0]), p[1], schemeOf(p[1]))
		}
	}
	diff := [][2]string{
		{"1.24.3", "1.25.0-alpine"}, // suffix presence differs
		{"v1.2.3", "1.3.0"},         // prefix differs
		{"1.2", "1.2.3"},            // segment count differs
		{"1.24.3-alpine", "1.24.3-ls45"},
		{"latest", "1.2.3"},
	}
	for _, p := range diff {
		if schemeOf(p[0]) == schemeOf(p[1]) {
			t.Errorf("schemeOf(%q)==schemeOf(%q)=%q, want different", p[0], p[1], schemeOf(p[0]))
		}
	}
}

func TestNewestNewer(t *testing.T) {
	mustVer := func(s string) *semver.Version {
		v, err := semver.NewVersion(s)
		if err != nil {
			t.Fatalf("NewVersion(%q): %v", s, err)
		}
		return v
	}
	cases := []struct {
		name     string
		cur      string
		tags     []string
		wantTag  string
		wantKind string
	}{
		{"major wins, off-scheme ignored", "1.24.3",
			[]string{"1.24.3", "1.24.4", "1.25.0", "1.25.0-alpine", "latest", "2.0.0"}, "2.0.0", "major"},
		{"minor", "1.24.3", []string{"1.24.3", "1.25.0"}, "1.25.0", "minor"},
		{"patch", "1.24.3", []string{"1.24.3", "1.24.4"}, "1.24.4", "patch"},
		{"nothing newer", "1.24.3", []string{"1.24.3", "1.24.1", "1.0.0"}, "", ""},
		{"same scheme only", "1.24.3-alpine",
			[]string{"1.25.0", "1.25.0-alpine", "1.26.0-alpine"}, "1.26.0-alpine", "minor"},
	}
	for _, tc := range cases {
		gotTag, gotKind := newestNewer(tc.cur, mustVer(tc.cur), tc.tags)
		if gotTag != tc.wantTag || gotKind != tc.wantKind {
			t.Errorf("%s: newestNewer = (%q,%q), want (%q,%q)", tc.name, gotTag, gotKind, tc.wantTag, tc.wantKind)
		}
	}
}

func TestCheckSemver(t *testing.T) {
	ref := "gitea/gitea:1.24.3"
	repo, _ := repoOf(ref)
	reg := &fakeReg{
		tags:    map[string][]string{repo: {"1.24.3", "1.25.0", "latest"}},
		digests: map[string]string{ref: "sha256:remote"},
	}
	res := Check(context.Background(), reg, ref, time.Now())
	if res.Kind != KindSemver.String() {
		t.Errorf("Kind = %q, want SEMVER", res.Kind)
	}
	if res.Current != "1.24.3" || res.Latest != "1.25.0" || res.UpdateKind != "minor" {
		t.Errorf("version fields = %+v", res)
	}
	if res.RegistryDigest != "sha256:remote" {
		t.Errorf("RegistryDigest = %q, want sha256:remote", res.RegistryDigest)
	}
	if res.Status != store.StatusOK {
		t.Errorf("Status = %q, want ok", res.Status)
	}
}

func TestCheckDigest(t *testing.T) {
	ref := "nginx:latest"
	reg := &fakeReg{digests: map[string]string{ref: "sha256:idx"}}
	res := Check(context.Background(), reg, ref, time.Now())
	if res.Kind != KindDigest.String() {
		t.Errorf("Kind = %q, want DIGEST", res.Kind)
	}
	if res.RegistryDigest != "sha256:idx" || res.Status != store.StatusOK {
		t.Errorf("res = %+v", res)
	}
	if reg.listN != 0 {
		t.Errorf("DIGEST mode listed tags %d times, want 0", reg.listN)
	}
}

func TestCheckAuthRequired(t *testing.T) {
	ref := "private/app:1.0.0"
	reg := &fakeReg{tagsErr: registry.ErrAuthRequired}
	res := Check(context.Background(), reg, ref, time.Now())
	if res.Status != store.StatusAuthRequired {
		t.Errorf("Status = %q, want auth-required", res.Status)
	}
}

func TestCheckRateLimited(t *testing.T) {
	ref := "nginx:latest"
	reg := &fakeReg{digErr: registry.ErrRateLimited}
	res := Check(context.Background(), reg, ref, time.Now())
	if res.Status != store.StatusRateLimited {
		t.Errorf("Status = %q, want rate-limited", res.Status)
	}
}

func TestShouldCheck(t *testing.T) {
	now := time.Now()
	window := time.Hour
	fresh := store.CheckResult{Status: store.StatusOK, CheckedAt: now.Add(-10 * time.Minute)}
	stale := store.CheckResult{Status: store.StatusOK, CheckedAt: now.Add(-2 * time.Hour)}
	errd := store.CheckResult{Status: store.StatusError, CheckedAt: now}

	cases := []struct {
		name  string
		prev  store.CheckResult
		found bool
		force bool
		want  bool
	}{
		{"absent", store.CheckResult{}, false, false, true},
		{"forced", fresh, true, true, true},
		{"prior error retried", errd, true, false, true},
		{"fresh cached", fresh, true, false, false},
		{"stale", stale, true, false, true},
	}
	for _, tc := range cases {
		if got := ShouldCheck(tc.prev, tc.found, now, window, tc.force); got != tc.want {
			t.Errorf("%s: ShouldCheck = %v, want %v", tc.name, got, tc.want)
		}
	}
}
