package web

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWritePreview(t *testing.T) {
	if os.Getenv("DW_WRITE_PREVIEW") != "1" {
		t.Skip("set DW_WRITE_PREVIEW=1 to emit browsable preview files")
	}
	r := testRenderer()
	sub, err := StaticFS()
	if err != nil {
		t.Fatal(err)
	}
	css, err := fs.ReadFile(sub, "dw-harbor.css")
	if err != nil {
		t.Fatal(err)
	}
	js, err := fs.ReadFile(sub, "app.js")
	if err != nil {
		t.Fatal(err)
	}

	dir := ".preview"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	invs, checks, din := sampleDashboard()
	agents, ain := sampleAgents()
	sinvs, schecks, sdin := stressDashboard()
	cdin := din
	cdin.Checking = true
	pages := []struct {
		name   string
		render func(*bytes.Buffer) error
	}{
		{"dashboard", func(b *bytes.Buffer) error { return r.RenderDashboard(b, BuildDashboard(invs, checks, din)) }},
		{"dashboard-stress", func(b *bytes.Buffer) error { return r.RenderDashboard(b, BuildDashboard(sinvs, schecks, sdin)) }},
		{"dashboard-checking", func(b *bytes.Buffer) error { return r.RenderDashboard(b, BuildDashboard(invs, checks, cdin)) }},
		{"agents", func(b *bytes.Buffer) error { return r.RenderAgents(b, BuildAgents(agents, ain)) }},
		{"setup", func(b *bytes.Buffer) error { return r.RenderSetup(b, setupClean()) }},
		{"login", func(b *bytes.Buffer) error { return r.RenderLogin(b, loginClean()) }},
	}
	for _, p := range pages {
		var buf bytes.Buffer
		if err := p.render(&buf); err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
		html := inlineAssets(buf.String(), string(css), string(js))
		path := filepath.Join(dir, p.name+".html")
		if err := os.WriteFile(path, []byte(html), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		t.Logf("wrote %s", path)
	}
}

func inlineAssets(html, css, js string) string {
	html = strings.Replace(html,
		`<link rel="stylesheet" href="/static/dw-harbor.css">`,
		"<style>\n"+css+"\n</style>", 1)
	html = strings.Replace(html,
		`<script src="/static/app.js" defer></script>`,
		"<script>\n"+js+"\n</script>", 1)
	return html
}
