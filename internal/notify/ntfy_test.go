package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPublishSendsHeadersAndBody(t *testing.T) {
	var (
		gotPath string
		gotHdr  http.Header
		gotBody string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotHdr = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "mytopic", "tok_secret", srv.Client())
	msg := Message{
		Title:    "gitea update",
		Body:     "gitea 1.24.3 -> 1.25.0 (minor) on home",
		Priority: PriorityHigh,
		Tags:     []string{"arrow_up", "whale"},
		Click:    "https://updates.example.com/",
	}
	if err := c.Publish(context.Background(), msg); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if gotPath != "/mytopic" {
		t.Errorf("path = %q, want /mytopic", gotPath)
	}
	if got := gotHdr.Get("Title"); got != msg.Title {
		t.Errorf("Title = %q, want %q", got, msg.Title)
	}
	if got := gotHdr.Get("Priority"); got != "4" {
		t.Errorf("Priority = %q, want 4", got)
	}
	if got := gotHdr.Get("Tags"); got != "arrow_up,whale" {
		t.Errorf("Tags = %q, want arrow_up,whale", got)
	}
	if got := gotHdr.Get("Click"); got != msg.Click {
		t.Errorf("Click = %q, want %q", got, msg.Click)
	}
	if got := gotHdr.Get("Authorization"); got != "Bearer tok_secret" {
		t.Errorf("Authorization = %q, want Bearer tok_secret", got)
	}
	if gotBody != msg.Body {
		t.Errorf("body = %q, want %q", gotBody, msg.Body)
	}
}

func TestPublishDisabledIsNoop(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()

	c := NewClient(srv.URL, "", "", srv.Client()) // no topic
	if c.Enabled() {
		t.Fatal("Enabled() = true with empty topic")
	}
	if err := c.Publish(context.Background(), Message{Body: "x"}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if hit {
		t.Error("disabled client made a request")
	}
}

func TestPublishNon2xxErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "t", "", srv.Client())
	if err := c.Publish(context.Background(), Message{Body: "x"}); err == nil {
		t.Error("expected an error on a 403 response")
	}
}

func TestPublishOmitsEmptyOptionalHeaders(t *testing.T) {
	var gotHdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHdr = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "t", "", srv.Client())
	if err := c.Publish(context.Background(), Message{Body: "x"}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	for _, h := range []string{"Title", "Tags", "Click", "Authorization", "Priority"} {
		if v := gotHdr.Get(h); v != "" {
			t.Errorf("header %s should be absent, got %q", h, v)
		}
	}
}
