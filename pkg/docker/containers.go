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
		// Attempt to stop the container and log an error if it fails.
		if err := execute.Execute("docker", "stop", name); err != nil {
			// Log the error. You can adjust how you log it (e.g. using a logger instead of fmt).
			fmt.Printf("failed to stop container %s: %v\n", name, err)
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

// ListDefaultContainers lists running containers using docker CLI instead of SDK.
func ListDefaultContainers() error {
	cmd := exec.Command("docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		fmt.Println("No running containers found.")
		return nil
	}

	for _, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}
		id, image, names := parts[0], parts[1], parts[2]
		fmt.Printf("%s\t%s\t%s\n", id[:12], image, names)
	}

	return nil
}
