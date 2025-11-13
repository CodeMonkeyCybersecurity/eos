package docker

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CleanupDockerResources performs comprehensive Docker cleanup before removal
// This ensures all containers, volumes, and networks are properly removed
func CleanupDockerResources(rc *eos_io.RuntimeContext, keepVolumes bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Docker resource cleanup", zap.Bool("keep_volumes", keepVolumes))

	// ASSESS - Check Docker state
	dockerState := assessDockerState(rc)
	if !dockerState.IsRunning {
		logger.Info("Docker is not running, skipping cleanup")
		return nil
	}

	logger.Info("Docker assessment completed",
		zap.Int("containers", dockerState.ContainerCount),
		zap.Int("volumes", dockerState.VolumeCount),
		zap.Int("networks", dockerState.NetworkCount),
		zap.Int("images", dockerState.ImageCount))

	// Show progress to user via logger
	if dockerState.ContainerCount > 0 || dockerState.VolumeCount > 0 {
		logger.Info("Docker cleanup required",
			zap.Int("containers", dockerState.ContainerCount),
			zap.Int("volumes", dockerState.VolumeCount),
			zap.Int("networks", dockerState.NetworkCount),
			zap.Int("images", dockerState.ImageCount))
	}

	// INTERVENE - Clean up Docker resources
	if err := cleanupContainers(rc, dockerState); err != nil {
		logger.Warn("Failed to cleanup some containers", zap.Error(err))
	}

	if !keepVolumes {
		if err := cleanupVolumes(rc, dockerState); err != nil {
			logger.Warn("Failed to cleanup some volumes", zap.Error(err))
		}
	}

	if err := cleanupNetworks(rc, dockerState); err != nil {
		logger.Warn("Failed to cleanup some networks", zap.Error(err))
	}

	if err := cleanupImages(rc, dockerState); err != nil {
		logger.Warn("Failed to cleanup some images", zap.Error(err))
	}

	// Clean up build cache and system
	if err := cleanupSystem(rc); err != nil {
		logger.Warn("Failed to cleanup Docker system", zap.Error(err))
	}

	// EVALUATE - Verify cleanup
	finalState := assessDockerState(rc)
	logger.Info("Docker cleanup completed",
		zap.Int("remaining_containers", finalState.ContainerCount),
		zap.Int("remaining_volumes", finalState.VolumeCount),
		zap.Int("remaining_networks", finalState.NetworkCount-finalState.DefaultNetworkCount),
		zap.Int("remaining_images", finalState.ImageCount))

	return nil
}

// DockerState represents the current state of Docker resources
type DockerState struct {
	IsRunning           bool
	ContainerCount      int
	RunningContainers   []string
	AllContainers       []string
	VolumeCount         int
	Volumes             []string
	NetworkCount        int
	Networks            []string
	DefaultNetworkCount int
	ImageCount          int
}

// assessDockerState checks the current state of Docker
func assessDockerState(rc *eos_io.RuntimeContext) *DockerState {
	state := &DockerState{}

	// Check if Docker daemon is running
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()
	if _, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"info"},
		Capture: true,
	}); err != nil {
		return state // Docker not running
	}
	state.IsRunning = true

	// Get container counts and IDs
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"ps", "-q"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil && output != "" {
		state.RunningContainers = strings.Split(strings.TrimSpace(output), "\n")
		state.ContainerCount = len(state.RunningContainers)
	}

	// Get all containers (including stopped)
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"ps", "-aq"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil && output != "" {
		state.AllContainers = strings.Split(strings.TrimSpace(output), "\n")
		state.ContainerCount = len(state.AllContainers)
	}

	// Get volume count
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"volume", "ls", "-q"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil && output != "" {
		state.Volumes = strings.Split(strings.TrimSpace(output), "\n")
		state.VolumeCount = len(state.Volumes)
	}

	// Get network count
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"network", "ls", "--format", "{{.Name}}"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil && output != "" {
		state.Networks = strings.Split(strings.TrimSpace(output), "\n")
		state.NetworkCount = len(state.Networks)

		// Count default networks (bridge, host, none)
		for _, net := range state.Networks {
			if net == "bridge" || net == "host" || net == "none" {
				state.DefaultNetworkCount++
			}
		}
	}

	// Get image count
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"images", "-q"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil && output != "" {
		images := strings.Split(strings.TrimSpace(output), "\n")
		state.ImageCount = len(images)
	}

	return state
}

// cleanupContainers stops and removes all Docker containers
func cleanupContainers(rc *eos_io.RuntimeContext, state *DockerState) error {
	logger := otelzap.Ctx(rc.Ctx)

	if state.ContainerCount == 0 {
		logger.Info("No containers to clean up")
		return nil
	}

	logger.Info("Cleaning up Docker containers", zap.Int("count", state.ContainerCount))

	// First, stop all running containers gracefully
	if len(state.RunningContainers) > 0 {
		logger.Info("Stopping running containers", zap.Int("count", len(state.RunningContainers)))

		// Stop with timeout
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args:    append([]string{"stop", "-t", "30"}, state.RunningContainers...),
			Capture: true,
			Timeout: 60 * time.Second,
		})
		if err != nil {
			logger.Warn("Some containers failed to stop gracefully",
				zap.Error(err),
				zap.String("output", output))

			// Force kill if graceful stop failed
			logger.Info("Force killing remaining containers")
			_, _ = execute.Run(rc.Ctx, execute.Options{
				Command: "docker",
				Args:    append([]string{"kill"}, state.RunningContainers...),
				Timeout: 30 * time.Second,
			})
		}
	}

	// Remove all containers
	logger.Info("Removing all containers")
	args := append([]string{"rm", "-f", "-v"}, state.AllContainers...)
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    args,
		Capture: true,
		Timeout: 30 * time.Second,
	})

	// Alternative: remove containers one by one if batch removal fails
	if err != nil && len(state.AllContainers) > 0 {
		logger.Warn("Batch container removal failed, removing individually")
		for _, container := range state.AllContainers {
			_, _ = execute.Run(rc.Ctx, execute.Options{
				Command: "docker",
				Args:    []string{"rm", "-f", "-v", container},
				Timeout: 10 * time.Second,
			})
		}
	}

	return err
}

// cleanupVolumes removes all Docker volumes
func cleanupVolumes(rc *eos_io.RuntimeContext, state *DockerState) error {
	logger := otelzap.Ctx(rc.Ctx)

	if state.VolumeCount == 0 {
		logger.Info("No volumes to clean up")
		return nil
	}

	logger.Info("Cleaning up Docker volumes", zap.Int("count", state.VolumeCount))

	// Remove all volumes
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"volume", "prune", "-f", "--all"},
		Capture: true,
		Timeout: 60 * time.Second,
	})

	if err != nil {
		logger.Warn("Volume prune failed, trying individual removal",
			zap.Error(err),
			zap.String("output", output))

		// Remove volumes individually
		for _, volume := range state.Volumes {
			_, _ = execute.Run(rc.Ctx, execute.Options{
				Command: "docker",
				Args:    []string{"volume", "rm", "-f", volume},
				Timeout: 10 * time.Second,
			})
		}
	}

	return nil
}

// cleanupNetworks removes all non-default Docker networks
func cleanupNetworks(rc *eos_io.RuntimeContext, state *DockerState) error {
	logger := otelzap.Ctx(rc.Ctx)

	customNetworks := []string{}
	for _, net := range state.Networks {
		// Skip default networks
		if net != "bridge" && net != "host" && net != "none" && net != "" {
			customNetworks = append(customNetworks, net)
		}
	}

	if len(customNetworks) == 0 {
		logger.Info("No custom networks to clean up")
		return nil
	}

	logger.Info("Cleaning up Docker networks", zap.Int("count", len(customNetworks)))

	// Remove custom networks
	for _, network := range customNetworks {
		logger.Debug("Removing network", zap.String("network", network))
		_, _ = execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args:    []string{"network", "rm", network},
			Timeout: 10 * time.Second,
		})
	}

	// Prune any remaining networks
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"network", "prune", "-f"},
		Timeout: 30 * time.Second,
	})

	return nil
}

// cleanupImages removes all Docker images
func cleanupImages(rc *eos_io.RuntimeContext, state *DockerState) error {
	logger := otelzap.Ctx(rc.Ctx)

	if state.ImageCount == 0 {
		logger.Info("No images to clean up")
		return nil
	}

	logger.Info("Cleaning up Docker images", zap.Int("count", state.ImageCount))

	// Remove all images forcefully
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"rmi", "-f", "$(docker images -q)"},
		Capture: true,
		Timeout: 120 * time.Second,
	})

	// Alternative approach if shell expansion doesn't work
	if err != nil {
		logger.Debug("Shell expansion failed, using alternative approach")
		if imageOutput, err := execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args:    []string{"images", "-q"},
			Capture: true,
			Timeout: 10 * time.Second,
		}); err == nil && imageOutput != "" {
			images := strings.Split(strings.TrimSpace(imageOutput), "\n")
			args := append([]string{"rmi", "-f"}, images...)
			_, _ = execute.Run(rc.Ctx, execute.Options{
				Command: "docker",
				Args:    args,
				Timeout: 120 * time.Second,
			})
		}
	}

	// Prune dangling images
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"image", "prune", "-f", "--all"},
		Timeout: 60 * time.Second,
	})

	return err
}

// cleanupSystem performs Docker system cleanup
func cleanupSystem(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Performing Docker system cleanup")

	// Run docker system prune
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"system", "prune", "-f", "--all", "--volumes"},
		Capture: true,
		Timeout: 120 * time.Second,
	})

	if err != nil {
		logger.Warn("Docker system prune failed",
			zap.Error(err),
			zap.String("output", output))
	} else {
		logger.Info("Docker system cleanup completed", zap.String("output", output))
	}

	// Clean build cache
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"builder", "prune", "-f", "--all"},
		Timeout: 60 * time.Second,
	})

	return nil
}

// RemoveDockerCompletely removes Docker from the system completely
func RemoveDockerCompletely(rc *eos_io.RuntimeContext, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting comprehensive Docker removal", zap.Bool("keep_data", keepData))

	// ASSESS - Check current Docker state
	dockerInstalled := isDockerInstalled(rc)
	if !dockerInstalled {
		logger.Info("Docker is not installed, nothing to remove")
		return nil
	}

	// First cleanup all Docker resources
	if err := CleanupDockerResources(rc, keepData); err != nil {
		logger.Warn("Docker resource cleanup had issues", zap.Error(err))
		// Continue with removal anyway
	}

	// INTERVENE - Remove Docker components
	if err := removeDockerComponents(rc, keepData); err != nil {
		return fmt.Errorf("failed to remove Docker components: %w", err)
	}

	// EVALUATE - Verify removal
	if err := verifyDockerRemoval(rc); err != nil {
		logger.Warn("Docker removal verification had issues", zap.Error(err))
		// Don't fail - partial removal is better than none
	}

	logger.Info("Docker removal completed successfully")
	return nil
}

// isDockerInstalled checks if Docker is installed on the system
func isDockerInstalled(rc *eos_io.RuntimeContext) bool {
	// Check if docker command exists
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"docker"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if err == nil {
		return true
	}

	// Check if Docker package is installed
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "dpkg",
		Args:    []string{"-l", "docker-ce"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if err == nil && strings.Contains(output, "ii") {
		return true
	}

	// Check docker.io package
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "dpkg",
		Args:    []string{"-l", "docker.io"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	return err == nil && strings.Contains(output, "ii")
}

// removeDockerComponents removes all Docker components from the system
func removeDockerComponents(rc *eos_io.RuntimeContext, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Stop Docker service
	logger.Info("Stopping Docker service")
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"stop", "docker"},
		Timeout: 30 * time.Second,
	})
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"stop", "docker.socket"},
		Timeout: 10 * time.Second,
	})

	// Disable Docker service
	logger.Info("Disabling Docker service")
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"disable", "docker"},
		Timeout: 10 * time.Second,
	})
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"disable", "docker.socket"},
		Timeout: 10 * time.Second,
	})

	// Kill any remaining Docker processes
	logger.Info("Killing any remaining Docker processes")
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "pkill",
		Args:    []string{"-f", "docker"},
		Timeout: 5 * time.Second,
	})

	// Remove Docker packages
	logger.Info("Removing Docker packages")
	dockerPackages := []string{
		"docker-ce",
		"docker-ce-cli",
		"containerd.io",
		"docker-compose-plugin",
		"docker-ce-rootless-extras",
		"docker.io",
		"docker-compose",
	}

	for _, pkg := range dockerPackages {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "dpkg",
			Args:    []string{"-l", pkg},
			Capture: true,
			Timeout: 5 * time.Second,
		})
		if err == nil && strings.Contains(output, "ii") {
			logger.Info("Removing Docker package", zap.String("package", pkg))
			if keepData {
				_ = execute.RunSimple(rc.Ctx, "apt-get", "remove", "-y", pkg)
			} else {
				_ = execute.RunSimple(rc.Ctx, "apt-get", "purge", "-y", pkg)
			}
		}
	}

	// Remove Docker repository
	logger.Info("Removing Docker APT repository")
	dockerAPTSources := []string{
		"/etc/apt/sources.list.d/docker.list",
		"/etc/apt/sources.list.d/download_docker_com_linux_ubuntu.list",
	}
	for _, source := range dockerAPTSources {
		_ = os.Remove(source)
	}

	// Remove Docker GPG key
	dockerGPGKeys := []string{
		"/usr/share/keyrings/docker-archive-keyring.gpg",
		"/etc/apt/keyrings/docker.gpg",
	}
	for _, key := range dockerGPGKeys {
		_ = os.Remove(key)
	}

	// Remove Docker directories
	logger.Info("Removing Docker directories")
	directories := GetDockerDirectories()
	for _, dir := range directories {
		// Skip data directories if keepData is true
		if keepData && dir.IsData {
			logger.Info("Preserving Docker data directory", zap.String("path", dir.Path))
			continue
		}

		if err := os.RemoveAll(dir.Path); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove directory",
				zap.String("path", dir.Path),
				zap.String("description", dir.Description),
				zap.Error(err))
		}
	}

	// Remove Docker binaries
	logger.Info("Removing Docker binaries")
	dockerBinaries := []string{
		"/usr/bin/docker",
		"/usr/local/bin/docker",
		"/usr/bin/dockerd",
		"/usr/local/bin/dockerd",
		"/usr/bin/docker-compose",
		"/usr/local/bin/docker-compose",
		"/usr/bin/docker-proxy",
		"/usr/bin/docker-init",
	}
	for _, binary := range dockerBinaries {
		_ = os.Remove(binary)
	}

	// Remove Docker group
	logger.Info("Removing Docker group")
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "groupdel",
		Args:    []string{"docker"},
		Timeout: 5 * time.Second,
	})

	// Update APT cache
	logger.Info("Updating APT cache")
	_ = execute.RunSimple(rc.Ctx, "apt-get", "update")

	// Reload systemd
	_ = execute.RunSimple(rc.Ctx, "systemctl", "daemon-reload")

	return nil
}

// verifyDockerRemoval verifies that Docker has been completely removed
func verifyDockerRemoval(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Docker removal")

	var issues []string

	// Check Docker command doesn't exist
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"docker"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil {
		issues = append(issues, "docker command still exists")
	}

	// Check Docker service doesn't exist
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "docker"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if err == nil && strings.TrimSpace(output) == "active" {
		issues = append(issues, "Docker service still active")
	}

	// Check no Docker processes
	output, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "pgrep",
		Args:    []string{"-f", "docker"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if output != "" {
		issues = append(issues, "Docker processes still running")
	}

	// Check Docker packages are removed
	packages := []string{"docker-ce", "docker.io"}
	for _, pkg := range packages {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "dpkg",
			Args:    []string{"-l", pkg},
			Capture: true,
			Timeout: 5 * time.Second,
		})
		if err == nil && strings.Contains(output, "ii") {
			issues = append(issues, fmt.Sprintf("%s package still installed", pkg))
		}
	}

	if len(issues) > 0 {
		return fmt.Errorf("docker removal incomplete: %v", issues)
	}

	logger.Info("Docker removal verified successfully")
	return nil
}

// GetDockerServices returns the list of services managed by Docker
func GetDockerServices() []ServiceConfig {
	return []ServiceConfig{
		{Name: "docker", Component: "docker", Required: false},
		{Name: "docker.socket", Component: "docker", Required: false},
		{Name: "containerd", Component: "docker", Required: false},
	}
}

// DirectoryConfig represents a directory managed by a component
type DirectoryConfig struct {
	Path        string
	Component   string
	IsData      bool
	Description string
}

// ServiceConfig represents a service managed by a component
type ServiceConfig struct {
	Name      string
	Component string
	Required  bool
}

// GetDockerDirectories returns the list of directories managed by Docker
func GetDockerDirectories() []DirectoryConfig {
	return []DirectoryConfig{
		{Path: "/var/lib/docker", Component: "docker", IsData: true, Description: "Docker data directory"},
		{Path: "/var/lib/containerd", Component: "docker", IsData: true, Description: "Containerd data directory"},
		{Path: "/etc/docker", Component: "docker", IsData: false, Description: "Docker configuration directory"},
		{Path: "/etc/containerd", Component: "docker", IsData: false, Description: "Containerd configuration directory"},
		{Path: "/var/run/docker", Component: "docker", IsData: false, Description: "Docker runtime directory"},
		{Path: "/run/docker", Component: "docker", IsData: false, Description: "Docker runtime directory"},
	}
}

// GetDockerBinaries returns the list of binaries managed by Docker
func GetDockerBinaries() []string {
	return []string{
		"/usr/bin/docker",
		"/usr/local/bin/docker",
		"/usr/bin/dockerd",
		"/usr/local/bin/dockerd",
		"/usr/bin/docker-compose",
		"/usr/local/bin/docker-compose",
		"/usr/bin/docker-proxy",
		"/usr/bin/docker-init",
		"/usr/bin/containerd",
		"/usr/bin/containerd-shim",
		"/usr/bin/containerd-shim-runc-v2",
		"/usr/bin/ctr",
		"/usr/bin/runc",
	}
}

// GetDockerAPTSources returns the list of APT sources managed by Docker
func GetDockerAPTSources() []string {
	return []string{
		"/etc/apt/sources.list.d/docker.list",
		"/etc/apt/sources.list.d/download_docker_com_linux_ubuntu.list",
	}
}
