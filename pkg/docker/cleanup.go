package docker

import (
	"context"
	"fmt"
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

	// Show progress to user
	if dockerState.ContainerCount > 0 || dockerState.VolumeCount > 0 {
		fmt.Printf("\nDocker cleanup required:\n")
		fmt.Printf("  - Containers: %d\n", dockerState.ContainerCount)
		fmt.Printf("  - Volumes: %d\n", dockerState.VolumeCount)
		fmt.Printf("  - Networks: %d\n", dockerState.NetworkCount)
		fmt.Printf("  - Images: %d\n", dockerState.ImageCount)
		fmt.Println()
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
			execute.Run(rc.Ctx, execute.Options{
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
			execute.Run(rc.Ctx, execute.Options{
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
			execute.Run(rc.Ctx, execute.Options{
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
		execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args:    []string{"network", "rm", network},
			Timeout: 10 * time.Second,
		})
	}

	// Prune any remaining networks
	execute.Run(rc.Ctx, execute.Options{
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
			execute.Run(rc.Ctx, execute.Options{
				Command: "docker",
				Args:    args,
				Timeout: 120 * time.Second,
			})
		}
	}

	// Prune dangling images
	execute.Run(rc.Ctx, execute.Options{
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
	execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"builder", "prune", "-f", "--all"},
		Timeout: 60 * time.Second,
	})

	return nil
}