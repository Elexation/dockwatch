// Package registry checks public container registries for newer tags and digests
// over anonymous access only, surfacing auth and rate limits as sentinel errors.
package registry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// Sentinel errors let callers classify failures without inspecting the HTTP transport; each wraps the original error.
var (
	ErrAuthRequired = errors.New("registry requires authentication")
	ErrRateLimited  = errors.New("registry rate limited")
	ErrNotFound     = errors.New("not found in registry")
)

// Client performs anonymous registry lookups.
type Client struct {
	base []remote.Option
}

// New builds a Client that does anonymous lookups only, never the Docker keychain.
func New() *Client {
	return &Client{
		base: []remote.Option{
			remote.WithAuth(authn.Anonymous),
			remote.WithRetryStatusCodes(), // empty set disables 429 auto-retry so the caller owns backoff
		},
	}
}

// ListTags returns all tags for repo (the library follows pagination).
func (c *Client) ListTags(ctx context.Context, repo string) ([]string, error) {
	r, err := name.NewRepository(repo)
	if err != nil {
		return nil, fmt.Errorf("parse repository %q: %w", repo, err)
	}
	tags, err := remote.List(r, c.opts(ctx)...)
	if err != nil {
		return nil, classify(err)
	}
	return tags, nil
}

// Created returns the build timestamp recorded in the image config ref resolves
// to, resolving a multi-arch index to the library's default platform. Publishers
// doing reproducible builds zero it, so a zero time with a nil error is valid.
func (c *Client) Created(ctx context.Context, ref string) (time.Time, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse reference %q: %w", ref, err)
	}
	desc, err := remote.Get(r, c.opts(ctx)...)
	if err != nil {
		return time.Time{}, classify(err)
	}
	img, err := desc.Image()
	if err != nil {
		return time.Time{}, classify(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return time.Time{}, classify(err)
	}
	return cf.Created.Time, nil
}

// Digest returns the index digest ref resolves to, matching Docker's repo digest so the two compare directly.
func (c *Client) Digest(ctx context.Context, ref string) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", fmt.Errorf("parse reference %q: %w", ref, err)
	}
	desc, err := remote.Get(r, c.opts(ctx)...)
	if err != nil {
		return "", classify(err)
	}
	return desc.Digest.String(), nil
}

func (c *Client) opts(ctx context.Context) []remote.Option {
	return append([]remote.Option{remote.WithContext(ctx)}, c.base...)
}

// classify maps a transport error's HTTP status to a sentinel; other errors pass through.
func classify(err error) error {
	var terr *transport.Error
	if errors.As(err, &terr) {
		switch terr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Errorf("%w: %v", ErrAuthRequired, err)
		case http.StatusTooManyRequests:
			return fmt.Errorf("%w: %v", ErrRateLimited, err)
		case http.StatusNotFound:
			return fmt.Errorf("%w: %v", ErrNotFound, err)
		}
	}
	return err
}
