// pkg/docker/containers.go

package docker

import (
	"fmt"
	"os/exec"
	"strings"

	"go.uber.org/zap"

	"eos/pkg/execute"
)

//
//---------------------------- STOP FUNCTIONS ---------------------------- //
//

// StopContainersBySubstring stops all containers whose names contain the given substring.
func StopContainersBySubstring(substring string) error {
	// Run "docker ps" with a filter for the substring.
	out, err := exec.Command("docker", "ps", "--filter", "name="+substring, "--format", "{{.Names}}").Output()
	if err != nil {
		return fmt.Errorf("failed to check container status: %w", err)
	}

	outputStr := strings.TrimSpace(string(out))
	if outputStr == "" {
		log.Info("No containers found matching substring", zap.String("substring", substring))
		return nil
	}

	// Split the output by newline to get each container name.
	containerNames := strings.Split(outputStr, "\n")
	for _, name := range containerNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		log.Info("Stopping container", zap.String("container", name))
		if err := execute.Execute("docker", "stop", name); err != nil {
			log.Error("Failed to stop container", zap.String("container", name), zap.Error(err))
		} else {
			log.Info("Container stopped successfully", zap.String("container", name))
		}
	}
	return nil
}

// StopContainer checks if a container with the given name is running, and stops it if it is.
func StopContainer(containerName string) error {
	// Run "docker ps" to check if the container is running.
	out, err := exec.Command("docker", "ps", "--filter", "name="+containerName, "--format", "{{.Names}}").Output()
	if err != nil {
		return fmt.Errorf("failed to check container status: %w", err)
	}

	containerNames := strings.TrimSpace(string(out))
	if containerNames == "" {
		// Container is not running.
		log.Info("Container not running", zap.String("container", containerName))
		return nil
	}

	log.Info("Container is running; stopping container", zap.String("container", containerName))
	// Run "docker stop" on the container.
	if err := execute.Execute("docker", "stop", containerName); err != nil {
		return fmt.Errorf("failed to stop container %s: %w", containerName, err)
	}

	log.Info("Container stopped successfully", zap.String("container", containerName))
	return nil
}

// StopContainers stops the specified Docker containers.
func StopContainers(containers []string) error {
	args := append([]string{"stop"}, containers...)
	if err := execute.Execute("docker", args...); err != nil {
		return fmt.Errorf("failed to stop containers %v: %w", containers, err)
	}

	log.Info("Containers stopped successfully", zap.Any("containers", containers))
	return nil
}

// RemoveContainers removes the specified Docker containers.
func RemoveContainers(containers []string) error {
	args := append([]string{"rm"}, containers...)
	if err := execute.Execute("docker", args...); err != nil {
		return fmt.Errorf("failed to remove containers %v: %w", containers, err)
	}
	log.Info("Containers removed successfully", zap.Any("containers", containers))
	return nil
}
