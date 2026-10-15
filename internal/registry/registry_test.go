package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fakeRegistry answers the manifest HEAD per head and counts manifest GETs.
func fakeRegistry(t *testing.T, head func(w http.ResponseWriter)) (host string, gets *int) {
	t.Helper()
	gets = new(int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/v2/team/app/manifests/1.0" && r.Method == http.MethodHead:
			head(w)
		default:
			*gets++
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), gets
}

func TestDigestUsesHead(t *testing.T) {
	host, gets := fakeRegistry(t, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		w.Header().Set("Content-Length", "123")
		w.Header().Set("Docker-Content-Digest", testDigest)
	})
	got, err := New().Digest(context.Background(), host+"/team/app:1.0")
	if err != nil || got != testDigest {
		t.Fatalf("Digest = %q, %v; want %s", got, err, testDigest)
	}
	if *gets != 0 {
		t.Errorf("%d manifest GETs, want 0: a GET counts against the pull limit", *gets)
	}
}

func TestDigestRateLimitSkipsGet(t *testing.T) {
	host, gets := fakeRegistry(t, func(w http.ResponseWriter) { w.WriteHeader(http.StatusTooManyRequests) })
	if _, err := New().Digest(context.Background(), host+"/team/app:1.0"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Digest err = %v, want ErrRateLimited", err)
	}
	if *gets != 0 {
		t.Errorf("%d manifest GETs after a 429, want 0", *gets)
	}
}

func TestClassifyStatusCodes(t *testing.T) {
	cases := []struct {
		code int
		want error
	}{
		{http.StatusUnauthorized, ErrAuthRequired},
		{http.StatusForbidden, ErrAuthRequired},
		{http.StatusTooManyRequests, ErrRateLimited},
		{http.StatusNotFound, ErrNotFound},
	}
	for _, tc := range cases {
		got := classify(&transport.Error{StatusCode: tc.code})
		if !errors.Is(got, tc.want) {
			t.Errorf("classify(%d) = %v, want %v", tc.code, got, tc.want)
		}
	}
}

func TestClassifyPassThrough(t *testing.T) {
	// A plain (non-transport) error is returned unchanged.
	plain := errors.New("dial tcp: i/o timeout")
	if got := classify(plain); !errors.Is(got, plain) {
		t.Errorf("classify(plain) = %v, want passthrough", got)
	}

	// An unmapped HTTP status (500) maps to none of the sentinels.
	got := classify(&transport.Error{StatusCode: http.StatusInternalServerError})
	if errors.Is(got, ErrAuthRequired) || errors.Is(got, ErrRateLimited) || errors.Is(got, ErrNotFound) {
		t.Errorf("classify(500) = %v, want no sentinel", got)
	}
}
