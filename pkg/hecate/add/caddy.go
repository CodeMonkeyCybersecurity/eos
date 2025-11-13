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

// IsAdminAPIReachable checks if Caddy Admin API is accessible from the host
// Returns true if reachable, false if connection refused or other network error
func IsAdminAPIReachable(rc *eos_io.RuntimeContext) bool {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Checking Caddy Admin API reachability",
		zap.String("host", hecate.CaddyAdminAPIHost),
		zap.Int("port", hecate.CaddyAdminAPIPort))

	// Create Caddy Admin API client
	caddyClient := hecate.NewCaddyAdminClient(hecate.CaddyAdminAPIHost)

	// Try to connect to Admin API
	if err := caddyClient.Health(rc.Ctx); err != nil {
		logger.Debug("Caddy Admin API not reachable",
			zap.Error(err),
			zap.String("url", fmt.Sprintf("http://%s:%d", hecate.CaddyAdminAPIHost, hecate.CaddyAdminAPIPort)))
		return false
	}

	logger.Debug("Caddy Admin API is reachable")
	return true
}

// RestartCaddyContainer restarts the Caddy container using Docker SDK
// This is a fallback when Admin API is unavailable (brief downtime)
func RestartCaddyContainer(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Restarting Caddy container",
		zap.String("container", hecate.CaddyContainerName),
		zap.String("reason", "Admin API unavailable or reload failed"))

	// Create Docker client
	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()

	// Restart container with 30 second timeout
	restartTimeout := 30
	stopOptions := dockertypes.StopOptions{
		Timeout: &restartTimeout,
	}

	if err := cli.ContainerRestart(rc.Ctx, hecate.CaddyContainerName, stopOptions); err != nil {
		return fmt.Errorf("failed to restart container: %w", err)
	}

	logger.Info("Caddy container restarted successfully")

	// Wait for container to be fully ready (see hecate.CaddyReloadWaitDuration)
	time.Sleep(hecate.CaddyReloadWaitDuration)

	// Verify container is running
	isRunning, err := IsCaddyRunning(rc)
	if err != nil {
		return fmt.Errorf("failed to verify Caddy status after restart: %w", err)
	}
	if !isRunning {
		return fmt.Errorf("Caddy container is not running after restart")
	}

	logger.Info("Caddy container verified running after restart")
	return nil
}

// ValidateCaddyConfig validates the Caddyfile using best available method
// Strategy selection (in order of preference):
//  1. Admin API (fastest, zero-downtime, requires port 2019 exposed)
//  2. Docker exec validation (fast, zero-downtime, always works)
//
// NOTE: This function NEVER restarts the container. Validation is non-destructive.
// Container restart only happens in ReloadCaddy as a last resort.
func ValidateCaddyConfig(rc *eos_io.RuntimeContext, caddyfilePath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Verify container is running before attempting validation
	isRunning, err := IsCaddyRunning(rc)
	if err != nil {
		return fmt.Errorf("failed to check Caddy status: %w", err)
	}
	if !isRunning {
		return fmt.Errorf("Caddy container is not running\n\n" +
			"Start Hecate with:\n" +
			"  cd /opt/hecate && docker-compose up -d")
	}

	// ASSESS: Check if Admin API is reachable
	if IsAdminAPIReachable(rc) {
		// Strategy 1: Admin API validation (preferred - fastest)
		logger.Debug("Validating Caddy configuration via Admin API")

		// Read the Caddyfile content
		caddyfileContent, err := os.ReadFile(caddyfilePath)
		if err != nil {
			return fmt.Errorf("failed to read Caddyfile: %w", err)
		}

		// Create Caddy Admin API client
		caddyClient := hecate.NewCaddyAdminClient(hecate.CaddyAdminAPIHost)

		// Validate by attempting to adapt the Caddyfile to JSON
		_, err = caddyClient.AdaptCaddyfile(rc.Ctx, string(caddyfileContent))
		if err != nil {
			return fmt.Errorf("Caddyfile validation failed: %w\n\n"+
				"The configuration has been rolled back to the previous working state.\n"+
				"File location: %s", err, caddyfilePath)
		}

		logger.Info("Caddy configuration validated successfully (via Admin API)")
		return nil
	}

	// Admin API not reachable - use docker exec validation
	logger.Warn("Admin API not reachable, using docker exec validation")

	// Strategy 2: Docker exec validation (zero-downtime, no port exposure needed)
	if err := hecate.ValidateCaddyfileLive(rc, caddyfilePath); err != nil {
		return fmt.Errorf("Caddyfile validation failed: %w\n\n"+
			"File location: %s\n"+
			"Check syntax: docker exec %s caddy validate --config /etc/caddy/Caddyfile",
			err, caddyfilePath, hecate.CaddyContainerName)
	}

	// Docker exec validation succeeded
	logger.Info("Caddy configuration validated successfully (via docker exec)")
	return nil
}

// reloadStrategy represents a reload strategy function
type reloadStrategy struct {
	name string
	fn   func(*eos_io.RuntimeContext, string, []byte) error
}

// ReloadCaddy reloads Caddy configuration using best available method
// Strategy selection (in order of preference):
//  1. Admin API (fastest, zero-downtime, requires port 2019 exposed)
//  2. Docker exec reload (fast, zero-downtime, always works)
//  3. Container restart (slow, brief downtime, guaranteed to work)
func ReloadCaddy(rc *eos_io.RuntimeContext, caddyfilePath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Read Caddyfile content once (used by all strategies)
	caddyfileContent, err := os.ReadFile(caddyfilePath)
	if err != nil {
		return fmt.Errorf("failed to read Caddyfile: %w", err)
	}

	// Define strategies in order of preference
	strategies := []reloadStrategy{
		{name: "Admin API", fn: reloadViaAdminAPI},
		{name: "Docker exec", fn: reloadViaDockerExec},
		{name: "Container restart", fn: reloadViaRestart},
	}

	// Try strategies in order
	var lastErr error
	for _, strategy := range strategies {
		logger.Debug("Attempting reload strategy",
			zap.String("strategy", strategy.name))

		err := strategy.fn(rc, caddyfilePath, caddyfileContent)
		if err == nil {
			logger.Info("Caddy reloaded successfully",
				zap.String("strategy", strategy.name))
			return nil
		}

		logger.Warn("Reload strategy failed, trying next",
			zap.String("strategy", strategy.name),
			zap.Error(err))
		lastErr = err
	}

	// All strategies failed
	return fmt.Errorf("Caddy reload failed (all strategies failed): %w\n\n"+
		"Check Caddy logs: docker logs %s",
		lastErr, hecate.CaddyContainerName)
}

// reloadViaAdminAPI attempts reload using Caddy Admin API
// CRITICAL P0.8: No separate reachability check to avoid TOCTOU race
// RATIONALE: Check + operation = race window where API could fail between them
// PATTERN: Attempt operation directly, rely on strategy fallback if it fails
func reloadViaAdminAPI(rc *eos_io.RuntimeContext, caddyfilePath string, content []byte) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Attempting Caddy reload via Admin API")

	// Create Admin API client
	caddyClient := hecate.NewCaddyAdminClient(hecate.CaddyAdminAPIHost)

	// CRITICAL P0.8: Attempt operation directly (no separate reachability check)
	// If Admin API is unreachable, LoadCaddyfile will fail and we'll fallback to next strategy
	// This is atomic - no TOCTOU race window
	if err := caddyClient.LoadCaddyfile(rc.Ctx, string(content)); err != nil {
		return fmt.Errorf("Admin API reload failed: %w", err)
	}

	// Wait for reload to complete
	time.Sleep(hecate.CaddyReloadWaitDuration)

	// Verify container is still running
	isRunning, err := IsCaddyRunning(rc)
	if err != nil || !isRunning {
		return fmt.Errorf("container not running after reload")
	}

	// Verify Admin API is still responsive
	if err := caddyClient.Health(rc.Ctx); err != nil {
		logger.Warn("Admin API health check failed after reload (continuing anyway)",
			zap.Error(err))
	}

	return nil
}

// reloadViaDockerExec attempts reload using docker exec
func reloadViaDockerExec(rc *eos_io.RuntimeContext, caddyfilePath string, content []byte) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check container is running
	isRunning, err := IsCaddyRunning(rc)
	if err != nil || !isRunning {
		return fmt.Errorf("container not running")
	}

	logger.Info("Reloading Caddy via docker exec")
	return hecate.ReloadCaddyViaExec(rc, caddyfilePath)
}

// reloadViaRestart attempts reload by restarting container
func reloadViaRestart(rc *eos_io.RuntimeContext, caddyfilePath string, content []byte) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn("Reloading Caddy via container restart (causes brief downtime ~2 seconds)")
	return RestartCaddyContainer(rc)
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
