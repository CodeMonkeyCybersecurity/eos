/* pkg/docker/helper.go */

package docker

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// DeployCompose performs the following actions:
// 1. Gets the current working directory and uses its base name as the application name.
// 2. Creates a target directory under /opt using the app name.
// 3. Searches for local docker-compose.yml or docker-compose.yaml files and copies them to the target directory.
// 4. Changes the ownership of the target directory to UID/GID 472.
// 5. Runs "docker compose up -d" in the target directory.
func DeployCompose() error {
	// Get the current working directory.
	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error getting current directory: %v", err)
	}

	// Use the current directory's base as the application name (e.g., "grafana").
	appDir := filepath.Base(currentDir)

	// Create the target directory under /opt (e.g., /opt/grafana).
	targetDir := filepath.Join("/opt", appDir)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("error creating target directory %s: %v", targetDir, err)
	}

	// Look for docker-compose.yml or docker-compose.yaml in the current directory.
	composeFiles, err := filepath.Glob("docker-compose.yml")
	if err != nil {
		return fmt.Errorf("error globbing docker-compose.yml: %v", err)
	}
	yamlFiles, err := filepath.Glob("docker-compose.yaml")
	if err != nil {
		return fmt.Errorf("error globbing docker-compose.yaml: %v", err)
	}
	composeFiles = append(composeFiles, yamlFiles...)

	if len(composeFiles) == 0 {
		fmt.Println("No docker-compose.yml or docker-compose.yaml file found in the current directory.")
		return nil
	}

	// For each compose file found, copy it to the target directory.
	for _, file := range composeFiles {
		destFile := filepath.Join(targetDir, filepath.Base(file))
		fmt.Printf("Copying %s to %s\n", file, destFile)
		if err := copyFile(file, destFile); err != nil {
			return fmt.Errorf("error copying file %s: %v", file, err)
		}
	}

	// Fix permissions on the target directory so that containers (e.g., Grafana) can write to volumes.
	// The official Grafana Docker image runs as UID/GID 472.
	fmt.Printf("Fixing ownership of %s to UID 472:472\n", targetDir)
	chownCmd := exec.Command("chown", "-R", "472:472", targetDir)
	chownCmd.Stdout = os.Stdout
	chownCmd.Stderr = os.Stderr
	if err := chownCmd.Run(); err != nil {
		return fmt.Errorf("error running chown: %v", err)
	}

	// Run "docker compose up -d" in the target directory.
	fmt.Printf("Running 'docker compose up -d' in %s\n", targetDir)
	dockerCmd := exec.Command("docker", "compose", "up", "-d")
	dockerCmd.Dir = targetDir
	dockerCmd.Stdout = os.Stdout
	dockerCmd.Stderr = os.Stderr
	if err := dockerCmd.Run(); err != nil {
		return fmt.Errorf("error running docker compose: %v", err)
	}

	fmt.Println("Docker compose is now up and running in the new directory.")
	return nil
}

// copyFile copies a file from src to dst, preserving file permissions.
func copyFile(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	// Ensure the source is a regular file.
	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	if _, err := io.Copy(destination, source); err != nil {
		return err
	}

	// Copy file permissions.
	if err := os.Chmod(dst, sourceFileStat.Mode()); err != nil {
		return err
	}

	return nil
}
