// pkg/docker/check.go

package docker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/docker/docker/client"
)

// CheckDockerContainers lists running containers using the Docker Go SDK.
func CheckDockerContainers() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	if len(containers) == 0 {
		fmt.Println("No running containers.")
		return nil
	}

	for _, container := range containers {
		fmt.Printf("Container ID: %s\tImage: %s\tNames: %v\n", container.ID[:12], container.Image, container.Names)
	}

	return nil
}

// CheckIfDockerInstalled checks if the Docker engine is available via the Go SDK.
func CheckIfDockerInstalled() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("docker not available: %w", err)
	}

	_, err = cli.Ping(ctx)
	if err != nil {
		return fmt.Errorf("docker engine not responding: %w", err)
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
