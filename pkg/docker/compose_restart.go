// pkg/docker/compose_restart.go
// Docker Compose service restart operations using Docker SDK
// RATIONALE: Restart specific services in a Compose project with health checks
// ARCHITECTURE: Uses Docker SDK (NOT shell commands) for better error handling

package docker

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RestartComposeServicesConfig controls compose service restart behavior
type RestartComposeServicesConfig struct {
	ProjectName  string        // Docker Compose project name (e.g., "hecate")
	ServiceNames []string      // Services to restart (e.g., ["server", "worker"])
	Timeout      time.Duration // Stop timeout before forceful kill
	HealthCheck  bool          // Wait for containers to reach "running" state
}

// RestartComposeServices restarts specific services in a Docker Compose project
// ASSESS: Find containers by project and service labels
// INTERVENE: Restart containers with timeout
// EVALUATE: Wait for running state, verify health
func RestartComposeServices(rc *eos_io.RuntimeContext, cfg *RestartComposeServicesConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	if cfg == nil {
		return fmt.Errorf("config is required")
	}

	if cfg.ProjectName == "" {
		return fmt.Errorf("project name is required")
	}

	if len(cfg.ServiceNames) == 0 {
		return fmt.Errorf("at least one service name is required")
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	logger.Info("Restarting Docker Compose services",
		zap.String("project", cfg.ProjectName),
		zap.Strings("services", cfg.ServiceNames),
		zap.Duration("timeout", cfg.Timeout),
		zap.Bool("health_check", cfg.HealthCheck))

	// Create Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	// ASSESS: Find containers by compose project label
	projectFilter := filters.NewArgs(
		filters.Arg("label", fmt.Sprintf("com.docker.compose.project=%s", cfg.ProjectName)),
	)

	containers, err := cli.ContainerList(rc.Ctx, containertypes.ListOptions{
		All:     true, // Include stopped containers
		Filters: projectFilter,
	})
	if err != nil {
		return fmt.Errorf("failed to list containers for project %s: %w", cfg.ProjectName, err)
	}

	if len(containers) == 0 {
		return fmt.Errorf("no containers found for project %s", cfg.ProjectName)
	}

	logger.Debug("Found containers in compose project",
		zap.String("project", cfg.ProjectName),
		zap.Int("total_containers", len(containers)))

	// ASSESS: Filter containers by service name
	var toRestart []containertypes.Summary
	for _, c := range containers {
		serviceName := c.Labels["com.docker.compose.service"]
		for _, targetService := range cfg.ServiceNames {
			if serviceName == targetService {
				toRestart = append(toRestart, c)
				logger.Debug("Service container matched for restart",
					zap.String("service", serviceName),
					zap.String("container_id", c.ID[:12]),
					zap.String("container_name", c.Names[0]))
				break
			}
		}
	}

	if len(toRestart) == 0 {
		return fmt.Errorf("no containers found for services %v in project %s", cfg.ServiceNames, cfg.ProjectName)
	}

	logger.Info("Found containers to restart",
		zap.Int("count", len(toRestart)),
		zap.String("project", cfg.ProjectName))

	// INTERVENE: Restart each container
	timeoutSeconds := int(cfg.Timeout.Seconds())
	restartedIDs := make([]string, 0, len(toRestart))

	for _, c := range toRestart {
		serviceName := c.Labels["com.docker.compose.service"]
		containerName := c.Names[0] // First name is primary

		logger.Info("Restarting container",
			zap.String("service", serviceName),
			zap.String("container", containerName),
			zap.Int("timeout_seconds", timeoutSeconds))

		stopOptions := containertypes.StopOptions{
			Timeout: &timeoutSeconds,
		}

		if err := cli.ContainerRestart(rc.Ctx, c.ID, stopOptions); err != nil {
			return fmt.Errorf("failed to restart container %s (service: %s): %w", containerName, serviceName, err)
		}

		logger.Info("Container restarted successfully",
			zap.String("service", serviceName),
			zap.String("container", containerName))

		restartedIDs = append(restartedIDs, c.ID)
	}

	// EVALUATE: Wait for containers to be healthy
	if cfg.HealthCheck {
		logger.Info("Waiting for containers to be healthy",
			zap.Int("count", len(restartedIDs)))

		// Wait a few seconds for containers to start
		time.Sleep(5 * time.Second)

		for _, containerID := range restartedIDs {
			if err := waitForContainerRunning(rc.Ctx, cli, containerID, 30*time.Second); err != nil {
				// Find original container info for better error message
				var serviceName, containerName string
				for _, c := range toRestart {
					if c.ID == containerID {
						serviceName = c.Labels["com.docker.compose.service"]
						containerName = c.Names[0]
						break
					}
				}

				return fmt.Errorf("container %s (service: %s) failed to start: %w", containerName, serviceName, err)
			}
		}

		logger.Info("All containers are running and healthy",
			zap.Int("count", len(restartedIDs)))
	}

	logger.Info("Docker Compose services restarted successfully",
		zap.String("project", cfg.ProjectName),
		zap.Strings("services", cfg.ServiceNames))

	return nil
}

// waitForContainerRunning polls container state until running or timeout
// EVALUATE: Verify container reached healthy state
func waitForContainerRunning(ctx context.Context, cli *client.Client, containerID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		inspect, err := cli.ContainerInspect(ctx, containerID)
		if err != nil {
			return fmt.Errorf("failed to inspect container: %w", err)
		}

		if inspect.State.Running {
			return nil
		}

		// If container is in a terminal state (not running and not starting), fail fast
		if inspect.State.Status != "created" && inspect.State.Status != "restarting" {
			return fmt.Errorf("container in unexpected state: %s", inspect.State.Status)
		}

		// Wait before retrying
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("timeout waiting for container to start after %s", timeout)
}
