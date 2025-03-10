package main

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
)

func main() {
	// Get current user details.
	usr, err := user.Current()
	if err != nil {
		log.Fatalf("Error fetching current user: %v", err)
	}
	homeDir := usr.HomeDir

	// Define paths for ~/.ssh and authorized_keys.
	sshDir := filepath.Join(homeDir, ".ssh")
	authKeys := filepath.Join(sshDir, "authorized_keys")

	// Create ~/.ssh if it doesn't exist.
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		if err := os.Mkdir(sshDir, 0700); err != nil {
			log.Fatalf("Error creating %s: %v", sshDir, err)
		}
		fmt.Printf("Created directory: %s with mode 0700\n", sshDir)
	} else {
		// Ensure directory has correct permissions.
		if err := os.Chmod(sshDir, 0700); err != nil {
			log.Fatalf("Error setting permissions on %s: %v", sshDir, err)
		}
		fmt.Printf("Set permissions for %s to 0700\n", sshDir)
	}

	// Check if authorized_keys exists.
	if _, err := os.Stat(authKeys); err == nil {
		// Set correct permissions on authorized_keys.
		if err := os.Chmod(authKeys, 0600); err != nil {
			log.Fatalf("Error setting permissions on %s: %v", authKeys, err)
		}
		fmt.Printf("Set permissions for %s to 0600\n", authKeys)
	} else {
		fmt.Printf("File %s does not exist; please copy your public key there (e.g., via ssh-copy-id)\n", authKeys)
	}

	fmt.Println("Passwordless SSH login should now work if your public key is in authorized_keys and the SSH server is configured properly.")
}
