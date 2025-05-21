// pkg/docker/check.go

package docker

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"

	cerr "github.com/cockroachdb/errors"
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
	_, err := execute.Run(execute.Options{
		Command: "docker",
		Args:    []string{"compose", "version"},
		Ctx:     context.TODO(),
	})
	if err == nil {
		return nil
	}

	_, err = execute.Run(execute.Options{
		Command: "docker-compose",
		Args:    []string{"version"},
		Ctx:     context.TODO(),
	})
	if err == nil {
		return nil
	}

	return errors.New("docker compose not found")
}

func CheckRunning() error {
	cmd := exec.Command("docker", "info")
	if err := cmd.Run(); err != nil {
		return cerr.Wrap(err, "Docker daemon is unavailable")
	}
	return nil
}
