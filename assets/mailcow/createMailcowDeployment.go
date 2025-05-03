package main

import (
	"fmt"
	"os"
	"os/exec"

	"go.uber.org/zap"
)

func main() {
	fmt.Println("Install mailcow")
	// Clone the mailcow-dockerized repository
	if err := runCommand("git", "clone", "https://github.com/mailcow/mailcow-dockerized"); err != nil {
		zap.L().Fatal("Error cloning repository: %v")
	}

	// Change working directory to "mailcow-dockerized"
	if err := os.Chdir("mailcow-dockerized"); err != nil {
		zap.L().Fatal("Error changing directory: %v")
	}

	// Generate a configuration file (this will prompt for a FQDN)
	fmt.Println("Generate a configuration file. Use a FQDN (host.domain.tld) as hostname when asked.")
	if err := runCommand("./generate_config.sh"); err != nil {
		zap.L().Fatal("Error generating configuration: %v")
	}

	// Open mailcow.conf in nano for editing
	fmt.Println("Change configuration if you want or need to.")
	if err := runCommand("nano", "mailcow.conf"); err != nil {
		zap.L().Fatal("Error opening mailcow.conf in nano: %v")
	}

	// Start mailcow by pulling images and starting the containers
	fmt.Println("Start mailcow")
	if err := runCommand("docker", "compose", "pull"); err != nil {
		zap.L().Fatal("Error pulling docker images: %v")
	}
	if err := runCommand("docker", "compose", "up", "-d"); err != nil {
		zap.L().Fatal("Error starting docker compose: %v")
	}

	// List running docker containers
	if err := runCommand("docker", "ps"); err != nil {
		zap.L().Fatal("Error listing docker containers: %v")
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
