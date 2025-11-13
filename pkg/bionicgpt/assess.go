// Package bionicgpt - Assessment helpers for BionicGPT deletion
package bionicgpt

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AssessInstallation checks what BionicGPT components are installed
// Returns: foundContainers, foundVolumes, installationExists
func AssessInstallation(rc *eos_io.RuntimeContext) ([]string, []string, bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Create Docker client (SDK)
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	foundContainers := []string{}
	foundVolumes := []string{}
	installationExists := false

	// Check for BionicGPT containers using SDK
	containerNames := []string{
		"bionicgpt-app", "bionicgpt-postgres", "bionicgpt-rag-engine",
		"bionicgpt-migrations", "bionicgpt-embeddings-api", "bionicgpt-chunking-engine",
	}

	for _, name := range containerNames {
		// Use Docker SDK to list containers with name filter
		listOptions := container.ListOptions{
			All: true, // Include stopped containers
			Filters: filters.NewArgs(
				filters.Arg("name", name),
			),
		}

		containers, err := cli.ContainerList(context.Background(), listOptions)
		if err != nil {
			logger.Warn("Failed to list containers",
				zap.String("filter", name),
				zap.Error(err))
			continue
		}

		if len(containers) > 0 {
			installationExists = true
			foundContainers = append(foundContainers, name)
			logger.Debug("Found container",
				zap.String("name", name),
				zap.String("id", containers[0].ID[:12]))
		}
	}

	// Check for volumes using SDK
	volumeNames := []string{VolumePostgresData, VolumeDocuments}
	for _, volName := range volumeNames {
		_, err := cli.VolumeInspect(context.Background(), volName)
		if err == nil {
			installationExists = true
			foundVolumes = append(foundVolumes, volName)
			logger.Debug("Found volume", zap.String("name", volName))
		}
	}

	logger.Info("Installation assessment complete",
		zap.Int("containers", len(foundContainers)),
		zap.Int("volumes", len(foundVolumes)),
		zap.Bool("installation_exists", installationExists))

	return foundContainers, foundVolumes, installationExists, nil
}
