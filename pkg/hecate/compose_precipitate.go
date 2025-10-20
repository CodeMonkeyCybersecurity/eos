// pkg/hecate/compose_precipitate.go
// Hecate-specific wrapper for docker compose precipitation

package hecate

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// PrecipitateHecateCompose extracts docker-compose.yml from running Hecate containers
func PrecipitateHecateCompose(rc *eos_io.RuntimeContext) (*docker.PrecipitatedCompose, error) {
	opts := docker.DefaultPrecipitateOptions()
	opts.ProjectName = "hecate"

	return docker.PrecipitateCompose(rc, opts)
}

// PrecipitateAndSaveCompose extracts compose from running Hecate containers and saves to file
func PrecipitateAndSaveCompose(rc *eos_io.RuntimeContext, outputPath string) error {
	opts := docker.DefaultPrecipitateOptions()
	opts.ProjectName = "hecate"

	if err := docker.PrecipitateAndSave(rc, opts, outputPath); err != nil {
		return fmt.Errorf("failed to precipitate Hecate compose: %w", err)
	}

	return nil
}
