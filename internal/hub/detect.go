// Package hub is the detection engine: it classifies each container's image and
// checks public registries for newer versions or republished digests.
package hub

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/elexation/dockwatch/internal/inventory"
	"github.com/elexation/dockwatch/internal/registry"
	"github.com/elexation/dockwatch/internal/store"
	"github.com/google/go-containerregistry/pkg/name"
)

// RegistryClient is the registry surface Check needs, declared here so detection is testable with a fake.
type RegistryClient interface {
	ListTags(ctx context.Context, repo string) ([]string, error)
	Digest(ctx context.Context, ref string) (string, error)
}

// Kind classifies how an image's updates are detected.
type Kind int

const (
	KindLocal  Kind = iota // no repo digests: locally built, not checkable
	KindSemver             // tag parses as a version: compare same-scheme tags
	KindDigest             // mutable tag (latest, stable, ...): compare registry digest
)

func (k Kind) String() string {
	switch k {
	case KindLocal:
		return "LOCAL"
	case KindSemver:
		return "SEMVER"
	case KindDigest:
		return "DIGEST"
	default:
		return "UNKNOWN"
	}
}

// Classify picks the detection mode: no repo digests means locally built (not checkable), else a parseable tag is SEMVER and the rest DIGEST.
func Classify(c inventory.Container) Kind {
	if len(c.RepoDigests) == 0 {
		return KindLocal
	}
	if tag, ok := tagOf(c.Image); ok && isSemver(tag) {
		return KindSemver
	}
	return KindDigest
}

// Check performs the registry-side check for a non-local reference; the caller
// handles LOCAL images (no registry call) first. A non-empty filter is the
// image's dw.tags regex; empty means the scheme heuristic applies.
func Check(ctx context.Context, reg RegistryClient, ref, filter string, now time.Time) store.CheckResult {
	res := store.CheckResult{Ref: ref, TagFilter: filter, CheckedAt: now}
	if tag, ok := tagOf(ref); ok && isSemver(tag) {
		res.Kind = KindSemver.String()
		checkSemver(ctx, reg, ref, tag, filter, &res)
	} else {
		res.Kind = KindDigest.String()
		checkDigest(ctx, reg, ref, &res)
	}
	return res
}

// ShouldCheck reports whether ref needs a fresh check: a success within window
// is reused, force always rechecks, a prior non-success is retried, and a
// changed tag filter invalidates the cached result.
func ShouldCheck(prev store.CheckResult, found bool, now time.Time, window time.Duration, force bool, filter string) bool {
	if force || !found || prev.Status != store.StatusOK || prev.TagFilter != filter {
		return true
	}
	return now.Sub(prev.CheckedAt) >= window
}

func checkSemver(ctx context.Context, reg RegistryClient, ref, tag, filter string, res *store.CheckResult) {
	cur, err := semver.NewVersion(tag)
	if err != nil { // isSemver already passed; defensive
		res.Status = store.StatusError
		res.Err = err.Error()
		return
	}
	res.Current = tag

	match := sameScheme(tag)
	if filter != "" {
		re, rerr := regexp.Compile("^(?:" + filter + ")$") // full-match; no substring surprises
		if rerr != nil {
			res.Status = store.StatusError
			res.Err = "invalid dw.tags regex: " + rerr.Error()
			return
		}
		match = re.MatchString
	}

	repo, ok := repoOf(ref)
	if !ok {
		res.Status = store.StatusError
		res.Err = "cannot parse repository from reference"
		return
	}
	tags, err := reg.ListTags(ctx, repo)
	if err != nil {
		applyErr(res, err)
		return
	}
	if newer, kind := newestNewer(cur, tags, match); newer != "" {
		res.Latest = newer
		res.UpdateKind = kind
	}

	// Record the tag's digest too, to catch a republish; best-effort, so a hiccup here doesn't fail the check.
	if dig, derr := reg.Digest(ctx, ref); derr == nil {
		res.RegistryDigest = dig
	}
	res.Status = store.StatusOK
}

func checkDigest(ctx context.Context, reg RegistryClient, ref string, res *store.CheckResult) {
	dig, err := reg.Digest(ctx, ref)
	if err != nil {
		applyErr(res, err)
		return
	}
	res.RegistryDigest = dig
	res.Status = store.StatusOK
}

func applyErr(res *store.CheckResult, err error) {
	switch {
	case errors.Is(err, registry.ErrAuthRequired):
		res.Status = store.StatusAuthRequired
	case errors.Is(err, registry.ErrRateLimited):
		res.Status = store.StatusRateLimited
	default:
		res.Status = store.StatusError
		res.Err = err.Error()
	}
}

// newestNewer returns the newest candidate tag (per match) strictly greater
// than cur, plus the bump kind. It returns "","" when nothing newer matches.
func newestNewer(cur *semver.Version, tags []string, match func(string) bool) (string, string) {
	var best *semver.Version
	var bestTag string
	for _, t := range tags {
		if !match(t) {
			continue
		}
		v, err := semver.NewVersion(t)
		if err != nil || v.Compare(cur) <= 0 {
			continue
		}
		if best == nil || v.Compare(best) > 0 {
			best, bestTag = v, t
		}
	}
	if best == nil {
		return "", ""
	}
	return bestTag, bumpKind(cur, best)
}

// sameScheme returns the v1 heuristic candidate predicate: tags shaped like curTag.
func sameScheme(curTag string) func(string) bool {
	want := schemeOf(curTag)
	return func(t string) bool { return schemeOf(t) == want }
}

func bumpKind(cur, newer *semver.Version) string {
	switch {
	case newer.Major() > cur.Major():
		return "major"
	case newer.Minor() > cur.Minor():
		return "minor"
	case newer.Patch() > cur.Patch():
		return "patch"
	default:
		return "" // differs only in prerelease/build; no clean bump kind
	}
}

// schemeOf signs a tag's shape (prefix, dotted-segment count, suffix with digit runs collapsed to "#") so only like-shaped tags compare as updates.
func schemeOf(tag string) string {
	i := 0
	for i < len(tag) && !isDigit(tag[i]) {
		i++
	}
	prefix := tag[:i]
	rest := tag[i:]

	j := 0
	for j < len(rest) && (isDigit(rest[j]) || rest[j] == '.') {
		j++
	}
	core := rest[:j]
	suffix := rest[j:]

	segments := 0
	if core != "" {
		segments = strings.Count(core, ".") + 1
	}
	return prefix + "|" + strconv.Itoa(segments) + "|" + collapseDigits(suffix)
}

func collapseDigits(s string) string {
	var b strings.Builder
	inDigit := false
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			if !inDigit {
				b.WriteByte('#')
				inDigit = true
			}
			continue
		}
		inDigit = false
		b.WriteByte(s[i])
	}
	return b.String()
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// tagOf returns an image's tag; a missing tag defaults to "latest", a digest-pinned reference returns ok=false.
func tagOf(image string) (string, bool) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return "", false
	}
	if t, ok := ref.(name.Tag); ok {
		return t.TagStr(), true
	}
	return "", false
}

func repoOf(ref string) (string, bool) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", false
	}
	return r.Context().Name(), true
}

func isSemver(tag string) bool {
	_, err := semver.NewVersion(tag)
	return err == nil
}
