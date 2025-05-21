// pkg/docker/check.go

package docker

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"

	cerr "github.com/cockroachdb/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

var log = zap.L().Named("docker")

type DockerCheckConfig struct {
	AllowMissingCompose bool `validate:"required"`
}

// CheckDockerContainers lists running containers using the docker CLI.
func CheckDockerContainers(ctx context.Context) error {
	ctx, span := telemetry.StartSpan(ctx, "docker.CheckDockerContainers")
	defer span.End()

	log.Info("Checking running Docker containers")
	out, err := execute.Run(execute.Options{
		Command: "docker",
		Args:    []string{"ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}"},
		Capture: true,
		Ctx:     ctx,
	})
	if err != nil {
		log.Error("Failed to list containers", zap.Error(err))
		return cerr.WithHint(err, "Ensure Docker is installed and running")
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		log.Info("No running containers")
		fmt.Println("No running containers.")
		return nil
	}

	for _, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) >= 3 {
			log.Info("Container info", zap.String("id", parts[0]), zap.String("image", parts[1]), zap.String("name", parts[2]))
			fmt.Printf("Container ID: %s\tImage: %s\tName: %s\n", parts[0][:12], parts[1], parts[2])
		}
	}
	return nil
}

// CheckIfDockerInstalled checks if Docker CLI is available and responding.
func CheckIfDockerInstalled(ctx context.Context) error {
	ctx, span := telemetry.StartSpan(ctx, "docker.CheckIfDockerInstalled")
	defer span.End()

	log.Info("Checking if Docker CLI is installed")
	_, err := execute.Run(execute.Options{
		Command: "docker",
		Args:    []string{"version", "--format", "'{{.Server.Version}}'"},
		Ctx:     ctx,
	})
	if err != nil {
		log.Error("Docker CLI not available", zap.Error(err))
		return cerr.WithHint(err, "Install Docker and ensure it’s in your PATH")
	}
	return nil
}

// CheckIfDockerComposeInstalled verifies docker compose availability.
func CheckIfDockerComposeInstalled(ctx context.Context) error {
	ctx, span := telemetry.StartSpan(ctx, "docker.CheckIfDockerComposeInstalled")
	defer span.End()

	log.Info("Checking for docker compose")
	commands := [][]string{
		{"docker", "compose", "version"},
		{"docker-compose", "version"},
	}
	for _, cmd := range commands {
		_, err := execute.Run(execute.Options{
			Command: cmd[0],
			Args:    cmd[1:],
			Ctx:     ctx,
		})
		if err == nil {
			return nil
		}
	}
	log.Warn("Docker Compose not found")
	return errors.New("docker compose not found")
}

// CheckRunning ensures Docker daemon is active.
func CheckRunning(ctx context.Context) error {
	ctx, span := telemetry.StartSpan(ctx, "docker.CheckRunning")
	defer span.End()

	log.Info("Checking if Docker daemon is running")
	_, err := execute.Run(execute.Options{
		Command: "docker",
		Args:    []string{"info"},
		Ctx:     ctx,
		Capture: true,
	})
	if err != nil {
		log.Error("Docker daemon not running", zap.Error(err))
		span.SetAttributes(attribute.String("hint", "Start Docker Desktop"))
		return cerr.WithHint(err, "Docker is not running. Please start Docker Desktop.")
	}
	return nil
}
