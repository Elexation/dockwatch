// Package inventory defines the hub<->agent wire contract and the local
// Docker-socket reader that produces it. The same structure is produced by the
// agent (over the wire) and by the hub for its own containers, so all
// downstream code is source-agnostic.
package inventory

// WireVersion is the contract version. Additive fields do not bump it; only
// breaking changes do.
const WireVersion = 1

// Docker daemon status values for Inventory.Docker.
const (
	DockerOK          = "ok"
	DockerUnavailable = "unavailable"
)

// Inventory is the full GET /v1/inventory response (and the hub's local
// equivalent).
type Inventory struct {
	V          int         `json:"v"`
	Host       string      `json:"host"`
	Docker     string      `json:"docker"` // DockerOK | DockerUnavailable
	Containers []Container `json:"containers"`
}

// Container is one running container as reported to the hub. Only dw.* labels
// are included; all others are stripped at the source for data minimization.
type Container struct {
	Name        string            `json:"name"`
	Image       string            `json:"image"`
	ImageID     string            `json:"image_id"`
	RepoDigests []string          `json:"repo_digests"`
	State       string            `json:"state"`
	Health      string            `json:"health,omitempty"`
	Arch        string            `json:"arch"`
	OS          string            `json:"os"`
	Labels      map[string]string `json:"labels"`
}
