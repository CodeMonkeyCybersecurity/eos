// pkg/docker/containers.go

package docker

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
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
		return nil
	}

	// Split the output by newline to get each container name.
	containerNames := strings.Split(outputStr, "\n")
	for _, name := range containerNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if err := execute.Execute("docker", "stop", name); err != nil {
		} else {
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
		return nil
	}

	// Run "docker stop" on the container.
	if err := execute.Execute("docker", "stop", containerName); err != nil {
		return fmt.Errorf("failed to stop container %s: %w", containerName, err)
	}

	return nil
}

// StopContainers stops the specified Docker containers.
func StopContainers(containers []string) error {
	args := append([]string{"stop"}, containers...)
	if err := execute.Execute("docker", args...); err != nil {
		return fmt.Errorf("failed to stop containers %v: %w", containers, err)
	}

	return nil
}

// RemoveContainers removes the specified Docker containers.
func RemoveContainers(containers []string) error {
	args := append([]string{"rm"}, containers...)
	if err := execute.Execute("docker", args...); err != nil {
		return fmt.Errorf("failed to remove containers %v: %w", containers, err)
	}
	return nil
}
