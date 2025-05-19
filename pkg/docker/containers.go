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

func StopContainersBySubstring(substring string) error {
	out, err := exec.Command("docker", "ps", "--filter", "name="+substring, "--format", "{{.Names}}").Output()
	if err != nil {
		return fmt.Errorf("failed to check container status: %w", err)
	}

	names := strings.Fields(string(out))
	for _, name := range names {
		if name == "" {
			continue
		}
		err := execute.RunSimple("docker", "stop", name)
		if err != nil {
			fmt.Printf("failed to stop container %s: %v\n", name, err)
		}
	}
	return nil
}

func StopContainer(containerName string) error {
	out, err := exec.Command("docker", "ps", "--filter", "name="+containerName, "--format", "{{.Names}}").Output()
	if err != nil {
		return fmt.Errorf("failed to check container status: %w", err)
	}

	if strings.TrimSpace(string(out)) == "" {
		return nil
	}

	err = execute.RunSimple("docker", "stop", containerName)
	if err != nil {
		return fmt.Errorf("failed to stop container %s: %w", containerName, err)
	}
	return nil
}

func StopContainers(containers []string) error {
	args := append([]string{"stop"}, containers...)
	err := execute.RunSimple("docker", args...)
	if err != nil {
		return fmt.Errorf("failed to stop containers %v: %w", containers, err)
	}
	return nil
}

func RemoveContainers(containers []string) error {
	args := append([]string{"rm"}, containers...)
	err := execute.RunSimple("docker", args...)
	if err != nil {
		return fmt.Errorf("failed to remove containers %v: %w", containers, err)
	}
	return nil
}

func ListDefaultContainers() error {
	cmd := exec.Command("docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		fmt.Println("No running containers found.")
		return nil
	}

	for _, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) >= 3 {
			fmt.Printf("%s\t%s\t%s\n", parts[0][:12], parts[1], parts[2])
		}
	}
	return nil
}
