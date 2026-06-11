package web

import (
	"errors"
	"html/template"
	"strings"
	"time"
)

// funcMap returns the template functions, closing over the renderer's clock for consistent relative times.
func (r *Renderer) funcMap() template.FuncMap {
	return template.FuncMap{
		"reltime":     func(t time.Time) string { return relativeTime(r.now(), t) },
		"expiryDate":  expiryDate,
		"wbrImageRef": wbrImageRef,
		"dict":        dict,
	}
}

// wbrImageRef returns the image ref with a <wbr> after each "/" and ":" so long
// refs wrap at boundaries. Each segment is HTML-escaped, so a hostile ref cannot inject.
func wbrImageRef(ref string) template.HTML {
	var b strings.Builder
	start := 0
	for i := 0; i < len(ref); i++ {
		if ref[i] == '/' || ref[i] == ':' {
			b.WriteString(template.HTMLEscapeString(ref[start : i+1]))
			b.WriteString("<wbr>")
			start = i + 1
		}
	}
	b.WriteString(template.HTMLEscapeString(ref[start:]))
	return template.HTML(b.String())
}

// expiryDate renders a cert expiry as "expires 2006-01-02"; a zero time yields "".
func expiryDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return "expires " + t.Format("2006-01-02")
}

// dict builds a map from alternating key/value pairs so a template can pass several values to a sub-template.
func dict(kv ...any) (map[string]any, error) {
	if len(kv)%2 != 0 {
		return nil, errors.New("dict: odd argument count")
	}
	m := make(map[string]any, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok {
			return nil, errors.New("dict: keys must be strings")
		}
		m[key] = kv[i+1]
	}
	return m, nil
}
