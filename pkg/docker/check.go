// pkg/docker/check.go

package docker

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// CheckDockerContainers lists running containers using the docker CLI.
func CheckDockerContainers() error {
	cmd := exec.Command("docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		fmt.Println("No running containers.")
		return nil
	}

	for _, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) >= 3 {
			fmt.Printf("Container ID: %s\tImage: %s\tName: %s\n", parts[0][:12], parts[1], parts[2])
		}
	}

	return nil
}

// CheckIfDockerInstalled checks if Docker CLI is available and responding.
func CheckIfDockerInstalled() error {
	cmd := exec.Command("docker", "version", "--format", "'{{.Server.Version}}'")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("docker CLI not available or not responding: %w", err)
	}
	return nil
}

// CheckIfDockerComposeInstalled checks for either 'docker compose' or 'docker-compose' and returns nil if one is found.
// This still shells out, since Docker SDK doesn't cover Compose.
func CheckIfDockerComposeInstalled() error {
	if err := RunCommand("docker", "compose", "version"); err == nil {
		return nil
	}
	if err := RunCommand("docker-compose", "version"); err == nil {
		return nil
	}
	return errors.New("docker compose not found")
}

// RunCommand executes a shell command and returns an error if it fails.
func RunCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("failed to execute command %s: %v\n", name, err)
		return err
	}
	return nil
}
