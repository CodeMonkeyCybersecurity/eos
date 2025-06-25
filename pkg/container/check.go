// pkg/docker/check.go

package container

import (
	"errors"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	cerr "github.com/cockroachdb/errors"
	"go.uber.org/zap"
)

type DockerCheckConfig struct {
	AllowMissingCompose bool `validate:"required"`
}

// CheckDockerContainers lists running containers using the docker CLI.
func CheckDockerContainers(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Checking running Docker containers")
	out, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}"},
		Capture: true,
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
func CheckIfDockerInstalled(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Checking if Docker CLI is installed")
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"version", "--format", "'{{.Server.Version}}'"},
	})
	if err != nil {
		log.Error("Docker CLI not available", zap.Error(err))
		return cerr.WithHint(err, "Install Docker and ensure it’s in your PATH")
	}
	return nil
}

// CheckIfDockerComposeInstalled verifies docker compose availability.
func CheckIfDockerComposeInstalled(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Checking for docker compose")
	commands := [][]string{
		{"docker", "compose", "version"},
		{"docker-compose", "version"},
	}
	for _, cmd := range commands {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: cmd[0],
			Args:    cmd[1:],
		})
		if err == nil {
			return nil
		}
	}
	log.Warn("Docker Compose not found")
	return errors.New("docker compose not found")
}

// EnsureDockerInstalled checks if Docker is installed and installs it if not.
// This provides a seamless experience for commands that depend on Docker.
func EnsureDockerInstalled(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	
	log.Info("Checking Docker installation")
	
	// First check if Docker is already available
	if err := CheckIfDockerInstalled(rc); err == nil {
		log.Info("Docker is already installed")
		
		// Also check if Docker is running
		if err := CheckRunning(rc); err != nil {
			log.Warn("Docker is installed but not running", zap.Error(err))
			return cerr.WithHint(err, "Please start Docker and try again")
		}
		
		log.Info("Docker is installed and running")
		return nil
	}
	
	log.Info("Docker not found, proceeding with installation")
	
	// Docker is not installed, so install it
	if err := InstallDocker(rc); err != nil {
		log.Error("Docker installation failed", zap.Error(err))
		return cerr.Wrap(err, "install Docker")
	}
	
	log.Info("Docker installation completed successfully")
	return nil
}

// CheckRunning ensures Docker daemon is active.
func CheckRunning(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Checking if Docker daemon is running")
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"info"},
		Capture: true,
	})
	if err != nil {
		log.Error("Docker daemon not running", zap.Error(err))
		return cerr.WithHint(err, "Docker is not running. Please start Docker Desktop.")
	}
	return nil
}
