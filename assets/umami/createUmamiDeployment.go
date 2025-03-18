package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

func main() {
	fmt.Println("instructions from 'https://umami.is/docs/install'")

	// Install Yarn
	fmt.Println("Install Yarn")
	if err := runCommand("sudo", "npm", "install", "-g", "yarn"); err != nil {
		log.Fatalf("Error installing Yarn: %v", err)
	}

	// Get the source code and install packages
	fmt.Println("Get the source code and install packages")
	if err := runCommand("git", "clone", "https://github.com/umami-software/umami.git"); err != nil {
		log.Fatalf("Error cloning Umami repository: %v", err)
	}

	// Change directory to "umami" and run "yarn install"
	fmt.Println("Changing directory to 'umami' and running 'yarn install'")
	if err := runCommandInDir("umami", "yarn", "install"); err != nil {
		log.Fatalf("Error running 'yarn install': %v", err)
	}

	// Configure Umami
	fmt.Println("Configure Umami")
	fmt.Println(`Configure Umami
Create an .env file with the following
DATABASE_URL={connection url}
The connection url is in the following format:
DATABASE_URL=postgresql://username:mypassword@localhost:5432/mydb`)

	// Install with Docker
	fmt.Println("Install with Docker")
	if err := runCommand("docker", "compose", "up", "-d"); err != nil {
		log.Fatalf("Error running 'docker compose up -d': %v", err)
	}
}

// runCommand runs a command with the provided arguments
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	// Print command's output in real time
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runCommandInDir runs a command in the specified directory
func runCommandInDir(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
