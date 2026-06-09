// Package notify delivers ntfy notifications for DockWatch update and lifecycle
// events. Delivery is best-effort: a failure is returned for the caller to log
// and is retried on the next cycle, never queued.
package notify

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const ntfyTimeout = 10 * time.Second

// Priority maps to ntfy's 1..5 message priority; 0 leaves it at the server default.
type Priority int

const (
	PriorityDefault Priority = 3
	PriorityHigh    Priority = 4
)

// Message is one ntfy notification.
type Message struct {
	Title    string
	Body     string
	Priority Priority
	Tags     []string // ntfy tag keywords (rendered as emoji where recognized)
	Click    string   // click-through URL; omitted when empty
}

// Client publishes to an ntfy server. A zero topic makes Publish a no-op so a
// hub started without DW_NTFY_TOPIC runs notification-free.
type Client struct {
	url   string
	topic string
	token string
	http  *http.Client
}

// NewClient builds an ntfy client for baseURL/topic. A nil hc gets a default
// client with a bounded timeout. token, when set, is sent as a Bearer header.
func NewClient(baseURL, topic, token string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: ntfyTimeout}
	}
	return &Client{
		url:   strings.TrimRight(baseURL, "/"),
		topic: topic,
		token: token,
		http:  hc,
	}
}

// Enabled reports whether a topic is configured; when false, Publish is a no-op.
func (c *Client) Enabled() bool { return c.topic != "" }

// Publish POSTs m to the configured topic. A disabled client returns nil without
// a request; a non-2xx response is an error.
func (c *Client) Publish(ctx context.Context, m Message) error {
	if !c.Enabled() {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/"+c.topic, bytes.NewBufferString(m.Body))
	if err != nil {
		return err
	}
	if m.Title != "" {
		req.Header.Set("Title", m.Title)
	}
	if m.Priority != 0 {
		req.Header.Set("Priority", strconv.Itoa(int(m.Priority)))
	}
	if len(m.Tags) > 0 {
		req.Header.Set("Tags", strings.Join(m.Tags, ","))
	}
	if m.Click != "" {
		req.Header.Set("Click", m.Click)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy publish: status %d", resp.StatusCode)
	}
	return nil
}
