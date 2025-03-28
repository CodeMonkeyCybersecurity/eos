// pkg/docker/check.go

package docker

import (
	"fmt"
	"os"
	"os/exec"

	"go.uber.org/zap"
)

// CheckDockerContainers runs "docker ps" and logs its output.
func CheckDockerContainers() error {
	log.Info("Checking running Docker containers...")
	cmd := exec.Command("docker", "ps")
	output, err := cmd.CombinedOutput()
	fmt.Println(string(output)) // Still prints to terminal for visibility

	if err != nil {
		log.Error("Failed to run docker ps", zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("failed to run docker ps: %v, output: %s", err, output)
	}

	log.Info("Docker ps output", zap.String("output", string(output)))
	return nil
}

// CheckIfDockerInstalled checks if docker is installed.
func CheckIfDockerInstalled() error {
	log.Info("Checking if Docker is installed")
	return RunCommand("docker", "--version")
}

// CheckIfDockerComposeInstalled checks for either 'docker compose' or 'docker-compose' and returns nil if one is found.
func CheckIfDockerComposeInstalled() error {
	log.Info("Checking if Docker Compose is installed (both plugin and legacy supported)")

	// First check for the newer 'docker compose' plugin
	if err := RunCommand("docker", "compose", "version"); err == nil {
		log.Info("Found 'docker compose' plugin")
		return nil
	}

	// Fallback to the older 'docker-compose' binary
	if err := RunCommand("docker-compose", "version"); err == nil {
		log.Info("Found legacy 'docker-compose' binary")
		return nil
	}

	log.Error("Neither 'docker compose' nor 'docker-compose' is available")
	return fmt.Errorf("docker compose not found")
}

// RunCommand executes a command and returns an error if it fails.
func RunCommand(name string, args ...string) error {
	log.Debug("Running command", zap.String("command", name), zap.Strings("args", args))
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Error("Command execution failed", zap.String("command", name), zap.Strings("args", args), zap.Error(err))
	}
	return err
}
