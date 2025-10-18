// Package fix provides automated fixes for common Mattermost issues
package fix

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Config holds configuration for Mattermost fix operations
type Config struct {
	DryRun          bool
	ComposeDir      string
	VolumesDir      string
	ContainerName   string
	ServiceName     string
	TargetUID       int
	TargetGID       int
	VolumesToFix    []string
	WatchLogSeconds int
}

// FixMattermostPermissions fixes common Mattermost permission issues
func FixMattermostPermissions(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Starting Mattermost permission fix",
		zap.Bool("dry_run", config.DryRun),
		zap.String("compose_dir", config.ComposeDir),
		zap.String("volumes_dir", config.VolumesDir))

	// ASSESS - Create Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()

	// Step 1: ASSESS - Check if container exists and is running
	logger.Info("Step 1: Checking Mattermost container status")
	containerID, isRunning, err := checkContainerStatus(rc, cli, config.ContainerName)
	if err != nil {
		return fmt.Errorf("failed to check container status: %w", err)
	}

	if containerID == "" {
		return fmt.Errorf("container %s not found", config.ContainerName)
	}

	logger.Info("Container found",
		zap.String("container_id", containerID[:12]),
		zap.Bool("is_running", isRunning))

	// Step 2: INTERVENE - Stop the container if running
	if isRunning {
		logger.Info("Step 2: Stopping Mattermost container")
		if !config.DryRun {
			if err := stopContainer(rc, cli, containerID); err != nil {
				return fmt.Errorf("failed to stop container: %w", err)
			}
			logger.Info("Container stopped successfully")
		} else {
			logger.Info("DRY-RUN: Would stop container", zap.String("container_id", containerID[:12]))
		}
	} else {
		logger.Info("Step 2: Container already stopped")
	}

	// Step 3: ASSESS - Check current volume permissions
	logger.Info("Step 3: Checking current volume permissions")
	for _, volumeName := range config.VolumesToFix {
		volumePath := filepath.Join(config.VolumesDir, "volumes", volumeName)
		if err := checkVolumePermissions(rc, volumePath); err != nil {
			logger.Warn("Volume permission check failed",
				zap.String("volume", volumeName),
				zap.Error(err))
		}
	}

	// Step 4: INTERVENE - Fix permissions
	logger.Info("Step 4: Fixing volume permissions",
		zap.Int("target_uid", config.TargetUID),
		zap.Int("target_gid", config.TargetGID))
	
	for _, volumeName := range config.VolumesToFix {
		volumePath := filepath.Join(config.VolumesDir, "volumes", volumeName)
		if !config.DryRun {
			if err := fixVolumePermissions(rc, volumePath, config.TargetUID, config.TargetGID); err != nil {
				return fmt.Errorf("failed to fix permissions for %s: %w", volumeName, err)
			}
			logger.Info("Permissions fixed",
				zap.String("volume", volumeName),
				zap.String("path", volumePath))
		} else {
			logger.Info("DRY-RUN: Would fix permissions",
				zap.String("volume", volumeName),
				zap.String("path", volumePath),
				zap.Int("uid", config.TargetUID),
				zap.Int("gid", config.TargetGID))
		}
	}

	// Step 5: EVALUATE - Verify permissions changed
	logger.Info("Step 5: Verifying permissions changed")
	for _, volumeName := range config.VolumesToFix {
		volumePath := filepath.Join(config.VolumesDir, "volumes", volumeName)
		if !config.DryRun {
			if err := checkVolumePermissions(rc, volumePath); err != nil {
				logger.Warn("Volume permission verification failed",
					zap.String("volume", volumeName),
					zap.Error(err))
			}
		}
	}

	// Step 6: INTERVENE - Start Mattermost container
	logger.Info("Step 6: Starting Mattermost container")
	if !config.DryRun {
		if err := startContainer(rc, cli, containerID); err != nil {
			return fmt.Errorf("failed to start container: %w", err)
		}
		logger.Info("Container started successfully")
	} else {
		logger.Info("DRY-RUN: Would start container", zap.String("container_id", containerID[:12]))
	}

	// Step 7: EVALUATE - Watch logs to verify successful startup
	if !config.DryRun && config.WatchLogSeconds > 0 {
		logger.Info("Step 7: Watching logs to verify startup",
			zap.Int("watch_seconds", config.WatchLogSeconds))
		if err := watchContainerLogs(rc, cli, containerID, config.WatchLogSeconds); err != nil {
			logger.Warn("Failed to watch logs", zap.Error(err))
		}
	} else if config.DryRun {
		logger.Info("DRY-RUN: Would watch logs for %d seconds", zap.Int("seconds", config.WatchLogSeconds))
	}

	logger.Info("Mattermost permission fix complete",
		zap.Bool("dry_run", config.DryRun),
		zap.Int("volumes_fixed", len(config.VolumesToFix)))

	return nil
}

// checkContainerStatus finds a container using Docker Compose labels (version-agnostic)
// This works with both Docker Compose v1 and v2, regardless of project naming
func checkContainerStatus(rc *eos_io.RuntimeContext, cli *client.Client, serviceName string) (string, bool, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Strategy 1: Use Docker Compose labels (most robust, works with v1 and v2)
	// Docker Compose adds these labels to all containers:
	// - com.docker.compose.service={service_name}
	// - com.docker.compose.project={project_name}
	filterArgs := filters.NewArgs()
	filterArgs.Add("label", fmt.Sprintf("com.docker.compose.service=%s", serviceName))
	
	logger.Debug("Searching for container using Docker Compose labels",
		zap.String("service_name", serviceName),
		zap.String("label_filter", fmt.Sprintf("com.docker.compose.service=%s", serviceName)))
	
	containers, err := cli.ContainerList(rc.Ctx, container.ListOptions{
		All:     true,
		Filters: filterArgs,
	})
	if err != nil {
		return "", false, fmt.Errorf("failed to list containers: %w", err)
	}

	// Found container(s) via Compose labels
	if len(containers) > 0 {
		c := containers[0] // Use first match (typically only one service instance)
		isRunning := c.State == "running"
		
		// Extract useful metadata from labels
		projectName := c.Labels["com.docker.compose.project"]
		serviceName := c.Labels["com.docker.compose.service"]
		containerNumber := c.Labels["com.docker.compose.container-number"]
		
		logger.Info("Container found via Docker Compose labels",
			zap.String("id", c.ID[:12]),
			zap.String("name", strings.TrimPrefix(c.Names[0], "/")),
			zap.String("state", c.State),
			zap.String("compose_project", projectName),
			zap.String("compose_service", serviceName),
			zap.String("compose_number", containerNumber))
		
		if len(containers) > 1 {
			logger.Warn("Multiple containers found for service, using first one",
				zap.Int("total_found", len(containers)))
		}
		
		return c.ID, isRunning, nil
	}

	// Strategy 2: Fallback to name-based search (for non-Compose containers)
	logger.Debug("No containers found via Compose labels, trying name-based search")
	
	allContainers, err := cli.ContainerList(rc.Ctx, container.ListOptions{All: true})
	if err != nil {
		return "", false, fmt.Errorf("failed to list containers: %w", err)
	}

	// Try common naming patterns
	namingPatterns := []string{
		serviceName,
		"/" + serviceName,
	}

	for _, c := range allContainers {
		for _, name := range c.Names {
			for _, pattern := range namingPatterns {
				if name == pattern {
					isRunning := c.State == "running"
					logger.Info("Container found via name matching (non-Compose)",
						zap.String("id", c.ID[:12]),
						zap.String("name", name),
						zap.String("state", c.State))
					return c.ID, isRunning, nil
				}
			}
		}
	}

	logger.Warn("Container not found",
		zap.String("service_name", serviceName),
		zap.String("hint", "Ensure the service is deployed via Docker Compose or the container name matches the service name"))

	return "", false, nil
}

func stopContainer(rc *eos_io.RuntimeContext, cli *client.Client, containerID string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	timeout := 30
	stopOptions := container.StopOptions{
		Timeout: &timeout,
	}
	
	if err := cli.ContainerStop(rc.Ctx, containerID, stopOptions); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	logger.Debug("Container stop command sent", zap.String("container_id", containerID[:12]))
	return nil
}

func startContainer(rc *eos_io.RuntimeContext, cli *client.Client, containerID string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	if err := cli.ContainerStart(rc.Ctx, containerID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	logger.Debug("Container start command sent", zap.String("container_id", containerID[:12]))
	return nil
}

func checkVolumePermissions(rc *eos_io.RuntimeContext, volumePath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	info, err := os.Stat(volumePath)
	if err != nil {
		return fmt.Errorf("failed to stat volume: %w", err)
	}

	logger.Info("Volume permissions",
		zap.String("path", volumePath),
		zap.String("mode", info.Mode().String()))

	// List directory contents
	entries, err := os.ReadDir(volumePath)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	logger.Info("Volume contents",
		zap.String("path", volumePath),
		zap.Int("item_count", len(entries)))

	for _, entry := range entries {
		info, _ := entry.Info()
		logger.Debug("Volume entry",
			zap.String("name", entry.Name()),
			zap.String("mode", info.Mode().String()),
			zap.Int64("size", info.Size()))
	}

	return nil
}

func fixVolumePermissions(rc *eos_io.RuntimeContext, volumePath string, uid, gid int) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Fixing volume permissions",
		zap.String("path", volumePath),
		zap.Int("uid", uid),
		zap.Int("gid", gid))

	// Walk the directory tree and fix permissions
	err := filepath.Walk(volumePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if err := os.Chown(path, uid, gid); err != nil {
			logger.Warn("Failed to chown",
				zap.String("path", path),
				zap.Error(err))
			return fmt.Errorf("failed to chown %s: %w", path, err)
		}

		logger.Debug("Permissions fixed",
			zap.String("path", path),
			zap.Int("uid", uid),
			zap.Int("gid", gid))

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk directory: %w", err)
	}

	return nil
}

func watchContainerLogs(rc *eos_io.RuntimeContext, cli *client.Client, containerID string, seconds int) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "50",
	}

	logs, err := cli.ContainerLogs(rc.Ctx, containerID, options)
	if err != nil {
		return fmt.Errorf("failed to get container logs: %w", err)
	}
	defer logs.Close()

	logger.Info("Watching container logs",
		zap.String("container_id", containerID[:12]),
		zap.Int("seconds", seconds))

	// Create a channel to signal when to stop watching
	done := make(chan bool)
	go func() {
		time.Sleep(time.Duration(seconds) * time.Second)
		done <- true
	}()

	// Read logs until timeout
	buf := make([]byte, 1024)
	for {
		select {
		case <-done:
			logger.Info("Log watching complete")
			return nil
		default:
			n, err := logs.Read(buf)
			if err != nil && err != io.EOF {
				return fmt.Errorf("failed to read logs: %w", err)
			}
			if n > 0 {
				logger.Info("Container log", zap.String("output", string(buf[:n])))
			}
			if err == io.EOF {
				return nil
			}
		}
	}
}
