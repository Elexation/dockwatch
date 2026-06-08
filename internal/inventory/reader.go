package inventory

import (
	"context"
	"strings"

	"github.com/moby/moby/client"
)

// dockerClient is the subset of the Docker API the reader needs. The real
// *client.Client satisfies it; tests supply a fake.
type dockerClient interface {
	ContainerList(ctx context.Context, options client.ContainerListOptions) (client.ContainerListResult, error)
	ImageInspect(ctx context.Context, imageID string, opts ...client.ImageInspectOption) (client.ImageInspectResult, error)
}

// Compile-time guarantee that the real client matches the interface above, so
// a signature drift in a future SDK bump fails the build here, not at the call.
var _ dockerClient = (*client.Client)(nil)

// Reader reads running containers from a Docker daemon and renders them as an
// Inventory. The agent uses it for its own host; the hub uses it for its local
// host. host is the display name stamped on the result.
type Reader struct {
	cli  dockerClient
	host string
}

// NewReader returns a Reader over cli, labeling results with host.
func NewReader(cli dockerClient, host string) *Reader {
	return &Reader{cli: cli, host: host}
}

// Read returns the current inventory. It always yields a usable Inventory: when
// the Docker daemon is unreachable the result has Docker == DockerUnavailable
// and no containers, and the underlying error is returned for logging only
// (callers should still use the Inventory). A failure to inspect a single
// image degrades that container's registry fields but never aborts the read.
func (r *Reader) Read(ctx context.Context) (Inventory, error) {
	inv := Inventory{
		V:          WireVersion,
		Host:       r.host,
		Docker:     DockerOK,
		Containers: []Container{},
	}

	list, err := r.cli.ContainerList(ctx, client.ContainerListOptions{})
	if err != nil {
		inv.Docker = DockerUnavailable
		return inv, err
	}

	cache := make(map[string]client.ImageInspectResult)
	for _, s := range list.Items {
		c := Container{
			Name:        containerName(s.Names),
			Image:       s.Image,
			ImageID:     s.ImageID,
			State:       string(s.State),
			Labels:      dwLabels(s.Labels),
			RepoDigests: []string{},
		}
		if s.Health != nil {
			c.Health = string(s.Health.Status)
		}

		insp, ok := cache[s.ImageID]
		if !ok {
			if got, ierr := r.cli.ImageInspect(ctx, s.ImageID); ierr == nil {
				cache[s.ImageID] = got
				insp, ok = got, true
			}
		}
		if ok {
			if len(insp.RepoDigests) > 0 {
				c.RepoDigests = insp.RepoDigests
			}
			c.Arch = insp.Architecture
			c.OS = insp.Os
		}

		inv.Containers = append(inv.Containers, c)
	}
	return inv, nil
}

func containerName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimPrefix(names[0], "/")
}

// dwLabels keeps only dw.* labels; everything else is stripped at the source.
func dwLabels(in map[string]string) map[string]string {
	out := make(map[string]string)
	for k, v := range in {
		if strings.HasPrefix(k, "dw.") {
			out[k] = v
		}
	}
	return out
}
