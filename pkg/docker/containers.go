// pkg/docker/containers.go

package docker

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/templates"
	"github.com/docker/docker/client"
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

func ListDefaultContainers() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	containers, err := cli.ContainerList(ctx, templates.DefaultContainerListOptions())
	if err != nil {
		return err
	}

	for _, c := range containers {
		fmt.Printf("%s\t%s\t%v\n", c.ID[:12], c.Image, c.Names)
	}

	return nil
}
