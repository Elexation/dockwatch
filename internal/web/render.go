package web

import (
	"embed"
	"html/template"
	"io"
	"io/fs"
	"time"
)

//go:embed templates
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// Renderer holds the parsed template set and a clock; it is safe for concurrent use.
type Renderer struct {
	tpl *template.Template
	now func() time.Time
}

// NewRenderer parses the embedded templates and returns a renderer on the wall clock.
func NewRenderer() (*Renderer, error) {
	return newRenderer(time.Now)
}

// newRenderer is NewRenderer with an injectable clock, for deterministic tests.
func newRenderer(now func() time.Time) (*Renderer, error) {
	r := &Renderer{now: now}
	sub, err := fs.Sub(templatesFS, "templates")
	if err != nil {
		return nil, err
	}
	t, err := template.New("dockwatch").Funcs(r.funcMap()).ParseFS(sub, "*.html")
	if err != nil {
		return nil, err
	}
	r.tpl = t
	return r, nil
}

func StaticFS() (fs.FS, error) {
	return fs.Sub(staticFS, "static")
}

// RenderSetup writes the first-run setup page.
func (r *Renderer) RenderSetup(w io.Writer, vm SetupVM) error {
	return r.tpl.ExecuteTemplate(w, "setup", vm)
}

// RenderLogin writes the login page.
func (r *Renderer) RenderLogin(w io.Writer, vm LoginVM) error {
	return r.tpl.ExecuteTemplate(w, "login", vm)
}

// RenderDashboard writes the dashboard page.
func (r *Renderer) RenderDashboard(w io.Writer, vm DashboardVM) error {
	return r.tpl.ExecuteTemplate(w, "dashboard.html", vm)
}

// RenderAgents writes the agents page.
func (r *Renderer) RenderAgents(w io.Writer, vm AgentsVM) error {
	return r.tpl.ExecuteTemplate(w, "agents.html", vm)
}
