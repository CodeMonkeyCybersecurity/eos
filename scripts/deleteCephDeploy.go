package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// runCommand executes a command with the given arguments and logs its output.
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	log.Printf("Running: %s %s\nOutput:\n%s", name, strings.Join(args, " "), output)
	if err != nil {
		return fmt.Errorf("error running %s %s: %v", name, strings.Join(args, " "), err)
	}
	return nil
}

// checkExecutable ensures the given executable exists in the PATH.
func checkExecutable(executable string) error {
	_, err := exec.LookPath(executable)
	if err != nil {
		return fmt.Errorf("executable %q not found in PATH", executable)
	}
	return nil
}

// getConfirmation prompts the user for confirmation before purging.
func getConfirmation() bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Are you sure you want to purge the entire Ceph deployment? This action is irreversible (Y/N): ")
	input, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading confirmation: %v", err)
		return false
	}
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}

func main() {
	log.Println("Starting Ceph purge automation using cephadm...")

	// Check that cephadm is available.
	if err := checkExecutable("cephadm"); err != nil {
		log.Fatalf("Pre-check failed: %v", err)
	}

	// Get user confirmation.
	if !getConfirmation() {
		log.Println("Purge aborted by user.")
		return
	}

	// Run the purge command. The "--force" flag will force the purge.
	purgeCmd := []string{"cephadm", "purge-cluster", "--force"}
	log.Println("Purging the Ceph cluster...")
	if err := runCommand(purgeCmd[0], purgeCmd[1:]...); err != nil {
		log.Fatalf("Failed to purge Ceph cluster: %v", err)
	}

	log.Println("Ceph cluster purge complete!")
}
