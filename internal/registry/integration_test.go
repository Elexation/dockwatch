//go:build integration

// These hit real registries over the network; run with: go test -tags integration ./internal/registry
package registry

import (
	"context"
	"testing"
	"time"
)

func TestListTagsLive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	tags, err := New().ListTags(ctx, "library/nginx")
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if len(tags) == 0 {
		t.Fatalf("ListTags returned no tags")
	}
}

func TestCreatedLive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	created, err := New().Created(ctx, "nginx:latest")
	if err != nil {
		t.Fatalf("Created: %v", err)
	}
	if created.IsZero() {
		t.Fatal("Created returned a zero time for nginx:latest")
	}
}

func TestDigestLive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	dig, err := New().Digest(ctx, "nginx:latest")
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if len(dig) < 7 || dig[:7] != "sha256:" {
		t.Fatalf("Digest = %q, want sha256:...", dig)
	}
}
