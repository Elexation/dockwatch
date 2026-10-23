package inventory

import (
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

// Ref returns image in one canonical spelling, so "nginx", "nginx:latest" and
// "docker.io/library/nginx:latest" key the same check and the same notification.
// Docker Hub names drop the implied registry and library/ namespace; any other
// registry keeps its host. A tag pinned to a digest ("app:1.2@sha256:...") keys
// as its tag: the pin only fixes which build runs, which the per-host digest
// join compares, so the tag is what the registry is asked about. An unparseable
// name is returned unchanged.
func Ref(image string) string {
	r, err := name.ParseReference(image)
	if err != nil {
		return image
	}
	repo := r.Context().RepositoryStr()
	if reg := r.Context().RegistryStr(); reg == name.DefaultRegistry {
		repo = strings.TrimPrefix(repo, "library/")
	} else {
		repo = reg + "/" + repo
	}
	if _, ok := r.(name.Digest); ok {
		if tag, ok := pinnedTag(image); ok {
			return repo + ":" + tag
		}
		return repo + "@" + r.Identifier()
	}
	return repo + ":" + r.Identifier()
}

// pinnedTag returns the tag written before a digest ("1.2" in "app:1.2@sha256:...").
// It checks the text, because the parsed digest reference discards the tag.
func pinnedTag(image string) (string, bool) {
	base, _, _ := strings.Cut(image, "@")
	last := base[strings.LastIndexByte(base, '/')+1:] // a registry port sits before the last slash
	_, tag, ok := strings.Cut(last, ":")
	return tag, ok && tag != ""
}
