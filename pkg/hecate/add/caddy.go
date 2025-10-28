// pkg/hecate/add/caddy.go

package add

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	dockertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NOTE: Constants moved to pkg/hecate/constants.go (CLAUDE.md Rule #12 - Single Source of Truth)
// Import hecate package to access: hecate.CaddyContainerName, CaddyfilePath, etc.

// ValidateCaddyConfig validates the Caddyfile using Caddy Admin API
// This validates by attempting to adapt the Caddyfile to JSON
func ValidateCaddyConfig(rc *eos_io.RuntimeContext, caddyfilePath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Validating Caddy configuration via Admin API")

	// Read the Caddyfile content
	caddyfileContent, err := os.ReadFile(caddyfilePath)
	if err != nil {
		return fmt.Errorf("failed to read Caddyfile: %w", err)
	}

	// Create Caddy Admin API client
	caddyClient := hecate.NewCaddyAdminClient(hecate.CaddyAdminAPIHost)

	// Validate by attempting to adapt the Caddyfile to JSON
	// If this succeeds, the Caddyfile is syntactically valid
	_, err = caddyClient.AdaptCaddyfile(rc.Ctx, string(caddyfileContent))
	if err != nil {
		return fmt.Errorf("Caddyfile validation failed: %w\n\n"+
			"The configuration has been rolled back to the previous working state.\n"+
			"File location: %s", err, caddyfilePath)
	}

	logger.Info("Caddy configuration validated successfully")
	return nil
}

// ReloadCaddy reloads Caddy configuration without restarting using Caddy Admin API
// This performs a zero-downtime reload, preserving TLS certificates and active connections
func ReloadCaddy(rc *eos_io.RuntimeContext, caddyfilePath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Reloading Caddy configuration via Admin API")

	// Read the Caddyfile content
	caddyfileContent, err := os.ReadFile(caddyfilePath)
	if err != nil {
		return fmt.Errorf("failed to read Caddyfile: %w", err)
	}

	// Create Caddy Admin API client
	caddyClient := hecate.NewCaddyAdminClient(hecate.CaddyAdminAPIHost)

	// Load the Caddyfile (adapt to JSON and apply)
	err = caddyClient.LoadCaddyfile(rc.Ctx, string(caddyfileContent))
	if err != nil {
		return fmt.Errorf("failed to reload Caddy: %w\n\n"+
			"The configuration has been rolled back to the previous working state.\n"+
			"Check Caddy logs with: docker logs %s", err, hecate.CaddyContainerName)
	}

	logger.Info("Caddy reloaded successfully")

	// Wait for reload to complete (see hecate.CaddyReloadWaitDuration)
	time.Sleep(hecate.CaddyReloadWaitDuration)

	// Verify Caddy is still running and healthy
	isRunning, err := IsCaddyRunning(rc)
	if err != nil {
		return fmt.Errorf("failed to verify Caddy status: %w", err)
	}

	if !isRunning {
		return fmt.Errorf("Caddy container is not running after reload\n\n"+
			"This is a critical error. Check Caddy logs with:\n"+
			"  docker logs %s", hecate.CaddyContainerName)
	}

	// Verify Admin API is still responsive
	if err := caddyClient.Health(rc.Ctx); err != nil {
		logger.Warn("Caddy Admin API health check failed after reload",
			zap.Error(err))
		// Don't fail the operation - container is running, API might be temporarily unresponsive
	}

	return nil
}

// IsCaddyRunning checks if the Caddy container is running using Docker SDK
func IsCaddyRunning(rc *eos_io.RuntimeContext) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Checking if Caddy container is running",
		zap.String("container", hecate.CaddyContainerName))

	// Create Docker client
	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return false, fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()

	// Create filters to find our specific container
	containerFilters := filters.NewArgs()
	containerFilters.Add("name", hecate.CaddyContainerName)

	// List containers matching the filter
	containers, err := cli.ContainerList(rc.Ctx, dockertypes.ListOptions{
		All:     false, // Only running containers
		Filters: containerFilters,
	})
	if err != nil {
		return false, fmt.Errorf("failed to list containers: %w", err)
	}

	// Check if we found the container and it's running
	if len(containers) == 0 {
		logger.Warn("Caddy container not found",
			zap.String("container", hecate.CaddyContainerName))
		return false, nil
	}

	// Container exists and is in the running list
	containerState := containers[0].State
	logger.Debug("Caddy container status",
		zap.String("state", containerState),
		zap.String("status", containers[0].Status))

	return containerState == "running", nil
}

// GetCaddyLogs retrieves the last N lines of Caddy logs using Docker SDK
func GetCaddyLogs(rc *eos_io.RuntimeContext, lines int) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Retrieving Caddy logs",
		zap.Int("lines", lines),
		zap.String("container", hecate.CaddyContainerName))

	// Create Docker client
	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()

	// Get container logs
	options := dockertypes.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       fmt.Sprintf("%d", lines),
	}

	logReader, err := cli.ContainerLogs(rc.Ctx, hecate.CaddyContainerName, options)
	if err != nil {
		return "", fmt.Errorf("failed to get Caddy logs: %w", err)
	}
	defer logReader.Close()

	// P1 #10: Docker logs are multiplexed with 8-byte headers per chunk
	// Must use stdcopy.StdCopy to properly demultiplex stdout and stderr
	var stdout, stderr bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdout, &stderr, logReader); err != nil {
		// If demultiplexing fails, still try to return what we got
		logger.Warn("Failed to demultiplex Docker logs, may contain headers",
			zap.Error(err))
		// Return both streams concatenated
		return stdout.String() + stderr.String(), nil
	}

	// Combine stdout and stderr (both are useful for debugging)
	return stdout.String() + stderr.String(), nil
}
