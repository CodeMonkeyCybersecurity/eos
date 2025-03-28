package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

func main() {
	fmt.Println("instructions https://docs.mattermost.com/install/install-docker.html#deploy-mattermost-on-docker-for-production-use")

	// Step 1: Clone the repository and enter the directory.
	fmt.Println("Cloning the repository and entering the directory...")
	if err := runCommand("git", "clone", "https://github.com/mattermost/docker"); err != nil {
		log.Fatalf("Error cloning repository: %v", err)
	}

	// Change directory to "docker"
	if err := os.Chdir("docker"); err != nil {
		log.Fatalf("Error changing directory to 'docker': %v", err)
	}

	// Step 2: Create your .env file by copying and adjusting the env.example file.
	fmt.Println("Creating .env file by copying env.example...")
	if err := runCommand("cp", "env.example", ".env"); err != nil {
		log.Fatalf("Error copying env.example to .env: %v", err)
	}

	// Step 3: Create the required directories.
	dirs := []string{
		"./volumes/app/mattermost/config",
		"./volumes/app/mattermost/data",
		"./volumes/app/mattermost/logs",
		"./volumes/app/mattermost/plugins",
		"./volumes/app/mattermost/client/plugins",
		"./volumes/app/mattermost/bleve-indexes",
	}
	fmt.Println("Creating required directories with proper permissions...")
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Error creating directory %s: %v", dir, err)
		}
	}

	// Step 4: Set the permissions on the mattermost directory.
	fmt.Println("Changing ownership of ./volumes/app/mattermost to UID 2000:2000...")
	if err := runCommand("sudo", "chown", "-R", "2000:2000", "./volumes/app/mattermost"); err != nil {
		log.Fatalf("Error changing ownership: %v", err)
	}

	// Step 5: Deploy Mattermost without nginx (Hecate will be your reverse proxy)
	fmt.Println("Deploying Mattermost without nginx...")
	if err := runCommand("sudo", "docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.without-nginx.yml", "up", "-d"); err != nil {
		log.Fatalf("Error deploying Mattermost: %v", err)
	}

	// Final message
	fmt.Println("Verify you can access 'http://localhost:8065'")
}

// runCommand executes a command with the provided arguments.
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	// Redirect command output to standard output and error.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
