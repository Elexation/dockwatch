package registry

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

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
