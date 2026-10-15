package inventory

import (
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

// Ref returns image in one canonical spelling, so "nginx", "nginx:latest" and
// "docker.io/library/nginx:latest" key the same check and the same notification.
// Docker Hub names drop the implied registry and library/ namespace; any other
// registry keeps its host. An unparseable name is returned unchanged.
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
		return repo + "@" + r.Identifier()
	}
	return repo + ":" + r.Identifier()
}
