// pkg/docker/check.go

package docker

import (
	"fmt"
	"os"
	"os/exec"
)

// CheckDockerContainers runs "docker ps" and logs its output.
func CheckDockerContainers() error {
	cmd := exec.Command( "docker", "ps")
	output, err := cmd.CombinedOutput()
	fmt.Println(string(output)) // Still prints to terminal for visibility

	if err != nil {
		return fmt.Errorf("failed to run docker ps: %v, output: %s", err, output)
	}

	return nil
}

// CheckIfDockerInstalled checks if docker is installed.
func CheckIfDockerInstalled() error {
	return RunCommand("docker", "--version")
}

// CheckIfDockerComposeInstalled checks for either 'docker compose' or 'docker-compose' and returns nil if one is found.
func CheckIfDockerComposeInstalled() error {

	// First check for the newer 'docker compose' plugin
	if err := RunCommand("docker", "compose", "version"); err == nil {
		return nil
	}

	// Fallback to the older 'docker-compose' binary
	if err := RunCommand("docker-compose", "version"); err == nil {
		return nil
	}

	return fmt.Errorf("docker compose not found")
}

/* RunCommand executes a command and returns an error if it fails. */
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
