package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	// Get the current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Error getting current directory: %v", err)
	}

	// Use the name of the current directory (e.g. "grafana, wazuh, nextcloud, etc.")
	appDir := filepath.Base(currentDir)
	fmt.Printf("Using current directory name (app_dir): %s\n", appDir)

	// Create the target directory in /opt (e.g. /opt/appname)
	targetDir := filepath.Join("/opt", appDir)
	fmt.Printf("Creating target directory: %s\n", targetDir)
	err = os.MkdirAll(targetDir, 0755)
	if err != nil {
		log.Fatalf("Error creating target directory: %v", err)
	}

	// Look for docker-compose.yml or docker-compose.yaml in the current directory
	composeFiles, err := filepath.Glob("docker-compose.yml")
	if err != nil {
		log.Fatalf("Error globbing docker-compose.yml: %v", err)
	}
	yamlFiles, err := filepath.Glob("docker-compose.yaml")
	if err != nil {
		log.Fatalf("Error globbing docker-compose.yaml: %v", err)
	}
	composeFiles = append(composeFiles, yamlFiles...)

	if len(composeFiles) == 0 {
		fmt.Println("No docker-compose.yml or docker-compose.yaml file found in the current directory.")
		return
	}

	// For each compose file found, copy it to the target directory
	for _, file := range composeFiles {
		destFile := filepath.Join(targetDir, filepath.Base(file))
		fmt.Printf("Copying %s to %s\n", file, destFile)
		if err := copyFile(file, destFile); err != nil {
			log.Fatalf("Error copying file %s: %v", file, err)
		}
	}

	// Fix permissions for the target directory so that Grafana can write to volumes or bind mounts.
	// The official Grafana Docker image runs as UID/GID 472.
	fmt.Printf("Fixing ownership of %s to UID 472:472\n", targetDir)
	chownCmd := exec.Command("chown", "-R", "472:472", targetDir)
	chownCmd.Stdout = os.Stdout
	chownCmd.Stderr = os.Stderr
	if err := chownCmd.Run(); err != nil {
		log.Fatalf("Error running chown: %v", err)
	}

	// Run 'docker compose up -d' in the new target directory
	fmt.Printf("Running 'docker compose up -d' in %s\n", targetDir)
	dockerCmd := exec.Command("docker", "compose", "up", "-d")
	dockerCmd.Dir = targetDir
	dockerCmd.Stdout = os.Stdout
	dockerCmd.Stderr = os.Stderr
	if err := dockerCmd.Run(); err != nil {
		log.Fatalf("Error running docker compose: %v", err)
	}
	fmt.Println("Docker compose is now up and running in the new directory.")
}

// copyFile copies a file from src to dst.
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

	// Copy file permissions
	if err := os.Chmod(dst, sourceFileStat.Mode()); err != nil {
		return err
	}

	return nil
}
