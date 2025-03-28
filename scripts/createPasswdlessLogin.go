package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
)

func printFileInfo(path string) {
	info, err := os.Stat(path)
	if err != nil {
		fmt.Printf("Error stating %s: %v\n", path, err)
		return
	}

	// File mode and permissions.
	fmt.Printf("File: %s\n", path)
	fmt.Printf("Mode: %v\n", info.Mode())

	// Try to get ownership info (works on Unix).
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		fmt.Printf("UID: %d, GID: %d\n", stat.Uid, stat.Gid)
	} else {
		fmt.Printf("Ownership info not available\n")
	}

	// If it's a file, show a snippet of its content.
	if !info.IsDir() {
		data, err := ioutil.ReadFile(path)
		if err == nil {
			fmt.Printf("Contents (first 300 bytes):\n%s\n", string(data)[:300])
		} else {
			fmt.Printf("Error reading file: %v\n", err)
		}
	}
	fmt.Println("-----")
}

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

	// Debug: Print home directory info.
	fmt.Printf("Current user: %s (%s)\n", usr.Username, homeDir)
	fmt.Println("-----")

	// Check .ssh directory.
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		fmt.Printf("Directory %s does not exist.\n", sshDir)
	} else {
		fmt.Printf("Directory %s exists.\n", sshDir)
		printFileInfo(sshDir)

		// Attempt to set directory permissions.
		if err := os.Chmod(sshDir, 0700); err != nil {
			log.Fatalf("Error setting permissions on %s: %v", sshDir, err)
		} else {
			fmt.Printf("Permissions for %s set to 0700\n", sshDir)
			printFileInfo(sshDir)
		}
	}

	// Check authorized_keys file.
	if _, err := os.Stat(authKeys); err == nil {
		fmt.Printf("File %s exists.\n", authKeys)
		printFileInfo(authKeys)

		// Attempt to set file permissions.
		if err := os.Chmod(authKeys, 0600); err != nil {
			log.Fatalf("Error setting permissions on %s: %v", authKeys, err)
		} else {
			fmt.Printf("Permissions for %s set to 0600\n", authKeys)
			printFileInfo(authKeys)
		}
	} else {
		fmt.Printf("File %s does not exist. Please copy your public key into this file (e.g., using ssh-copy-id).\n", authKeys)
	}

	fmt.Println("Debugging complete. Verify that your public key is present in authorized_keys and that permissions/ownership are correct.")
}
