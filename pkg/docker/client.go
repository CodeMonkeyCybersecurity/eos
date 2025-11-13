package docker

import (
	"context"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

const defaultTimeout = 5 * time.Second

// New establishes a Docker client using environment configuration with API version negotiation enabled.
func New(ctx context.Context) (*client.Client, error) {
	return client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
}

// Ping validates connectivity with the Docker daemon within a short timeout window.
func Ping(ctx context.Context, cli *client.Client) error {
	pingCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	_, err := cli.Ping(pingCtx)
	return err
}

// ListContainers performs a lightweight container listing to confirm API access without retrieving the full dataset.
func ListContainers(ctx context.Context, cli *client.Client, limit int) ([]types.Container, error) {
	listCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	return cli.ContainerList(listCtx, container.ListOptions{Limit: limit})
}
