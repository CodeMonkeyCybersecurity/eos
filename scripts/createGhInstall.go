package main

import (
	"fmt"
	"os"
	"os/exec"
)

// runCommand executes a command with given arguments,
// streams its output to stdout/stderr, and returns an error if any.
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	// Connect the command’s standard output and error to the process’s output.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func main() {
	fmt.Println("Step 1: Installing dnf-command(config-manager)...")
	err := runCommand("sudo", "dnf", "install", "dnf-command(config-manager)")
	if err != nil {
		fmt.Printf("Error in installing dnf-command: %v\n", err)
		return
	}

	fmt.Println("Step 2: Adding GitHub CLI repository...")
	err = runCommand("sudo", "dnf", "config-manager", "--add-repo", "https://cli.github.com/packages/rpm/gh-cli.repo")
	if err != nil {
		fmt.Printf("Error in adding repository: %v\n", err)
		return
	}

	fmt.Println("Step 3: Installing GitHub CLI (gh)...")
	err = runCommand("sudo", "dnf", "install", "-y", "gh")
	if err != nil {
		fmt.Printf("Error in installing gh: %v\n", err)
		return
	}

	fmt.Println("Step 4: Upgrading gh...")
	err = runCommand("sudo", "dnf", "update", "gh")
	if err != nil {
		fmt.Printf("Error in updating gh: %v\n", err)
		return
	}

	fmt.Println("Installation and upgrade complete!")
}
