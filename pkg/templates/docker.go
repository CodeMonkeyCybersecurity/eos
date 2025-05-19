// pkg/templates/docker.go
package templates

import (
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
)

// DefaultContainerListOptions returns the default options for listing containers.
// This mimics 'docker ps' (running containers only).
func DefaultContainerListOptions() types.ContainerListOptions {
	return types.ContainerListOptions{
		All:     false,             // only show running containers
		Limit:   0,                 // no limit
		Size:    false,             // don't include container size
		Filters: filters.NewArgs(), // no filters by default
	}
}
