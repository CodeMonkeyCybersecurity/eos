package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

func main() {
	fmt.Println("Install mailcow")
	// Clone the mailcow-dockerized repository
	if err := runCommand("git", "clone", "https://github.com/mailcow/mailcow-dockerized"); err != nil {
		log.Fatalf("Error cloning repository: %v", err)
	}

	// Change working directory to "mailcow-dockerized"
	if err := os.Chdir("mailcow-dockerized"); err != nil {
		log.Fatalf("Error changing directory: %v", err)
	}

	// Generate a configuration file (this will prompt for a FQDN)
	fmt.Println("Generate a configuration file. Use a FQDN (host.domain.tld) as hostname when asked.")
	if err := runCommand("./generate_config.sh"); err != nil {
		log.Fatalf("Error generating configuration: %v", err)
	}

	// Open mailcow.conf in nano for editing
	fmt.Println("Change configuration if you want or need to.")
	if err := runCommand("nano", "mailcow.conf"); err != nil {
		log.Fatalf("Error opening mailcow.conf in nano: %v", err)
	}

	// Start mailcow by pulling images and starting the containers
	fmt.Println("Start mailcow")
	if err := runCommand("docker", "compose", "pull"); err != nil {
		log.Fatalf("Error pulling docker images: %v", err)
	}
	if err := runCommand("docker", "compose", "up", "-d"); err != nil {
		log.Fatalf("Error starting docker compose: %v", err)
	}

	// List running docker containers
	if err := runCommand("docker", "ps"); err != nil {
		log.Fatalf("Error listing docker containers: %v", err)
	}

	// Final instructions and credentials
	fmt.Println("You can now access https://${MAILCOW_HOSTNAME} with the default credentials")
	fmt.Println("username:")
	fmt.Println("admin")
	fmt.Println("password:")
	fmt.Println("moohoo")
}

// runCommand executes a command with the given arguments, piping input, output, and errors.
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	// Allow interactive commands by connecting standard input/output.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}
