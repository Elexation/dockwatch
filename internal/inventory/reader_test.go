package inventory

import (
	"context"
	"errors"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/client"
)

type fakeDocker struct {
	list         client.ContainerListResult
	listErr      error
	inspect      map[string]client.ImageInspectResult
	inspectCalls int
}

func (f *fakeDocker) ContainerList(_ context.Context, _ client.ContainerListOptions) (client.ContainerListResult, error) {
	return f.list, f.listErr
}

func (f *fakeDocker) ImageInspect(_ context.Context, id string, _ ...client.ImageInspectOption) (client.ImageInspectResult, error) {
	f.inspectCalls++
	return f.inspect[id], nil
}

func summary(name, image, imageID string, labels map[string]string, health string) container.Summary {
	s := container.Summary{
		Names:   []string{"/" + name},
		Image:   image,
		ImageID: imageID,
		State:   "running",
		Labels:  labels,
	}
	if health != "" {
		s.Health = &container.HealthSummary{Status: container.HealthStatus(health)}
	}
	return s
}

func TestReadDockerDown(t *testing.T) {
	r := NewReader(&fakeDocker{listErr: errors.New("dial unix: no such file")}, "home")
	inv, err := r.Read(context.Background())
	if err == nil {
		t.Errorf("expected error for logging, got nil")
	}
	if inv.Docker != DockerUnavailable {
		t.Errorf("Docker = %q, want %q", inv.Docker, DockerUnavailable)
	}
	if inv.Host != "home" || inv.V != WireVersion {
		t.Errorf("inv = %+v", inv)
	}
	if len(inv.Containers) != 0 {
		t.Errorf("containers = %d, want 0", len(inv.Containers))
	}
}

func TestReadHappyPath(t *testing.T) {
	f := &fakeDocker{
		list: client.ContainerListResult{Items: []container.Summary{
			summary("gitea", "gitea/gitea:1.24.3", "sha256:abc",
				map[string]string{"dw.watch": "false", "com.docker.compose.project": "x"}, "healthy"),
		}},
		inspect: map[string]client.ImageInspectResult{
			"sha256:abc": {InspectResponse: image.InspectResponse{
				ID:           "sha256:abc",
				RepoDigests:  []string{"gitea/gitea@sha256:def"},
				Architecture: "amd64",
				Os:           "linux",
			}},
		},
	}
	inv, err := NewReader(f, "home").Read(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inv.Docker != DockerOK || len(inv.Containers) != 1 {
		t.Fatalf("inv = %+v", inv)
	}
	c := inv.Containers[0]
	if c.Name != "gitea" {
		t.Errorf("Name = %q, want gitea (leading slash trimmed)", c.Name)
	}
	if c.Image != "gitea/gitea:1.24.3" || c.ImageID != "sha256:abc" || c.State != "running" {
		t.Errorf("container basics = %+v", c)
	}
	if c.Health != "healthy" {
		t.Errorf("Health = %q, want healthy", c.Health)
	}
	if len(c.RepoDigests) != 1 || c.RepoDigests[0] != "gitea/gitea@sha256:def" {
		t.Errorf("RepoDigests = %v", c.RepoDigests)
	}
	if c.Arch != "amd64" || c.OS != "linux" {
		t.Errorf("platform = %q/%q", c.Arch, c.OS)
	}
	if len(c.Labels) != 1 || c.Labels["dw.watch"] != "false" {
		t.Errorf("Labels = %v, want only dw.* kept", c.Labels)
	}
}

func TestImageInspectCached(t *testing.T) {
	f := &fakeDocker{
		list: client.ContainerListResult{Items: []container.Summary{
			summary("a", "img:1", "sha256:same", nil, ""),
			summary("b", "img:1", "sha256:same", nil, ""),
		}},
		inspect: map[string]client.ImageInspectResult{
			"sha256:same": {InspectResponse: image.InspectResponse{Architecture: "arm64", Os: "linux"}},
		},
	}
	inv, err := NewReader(f, "local").Read(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(inv.Containers) != 2 {
		t.Fatalf("containers = %d, want 2", len(inv.Containers))
	}
	if f.inspectCalls != 1 {
		t.Errorf("inspectCalls = %d, want 1 (shared image inspected once)", f.inspectCalls)
	}
}
