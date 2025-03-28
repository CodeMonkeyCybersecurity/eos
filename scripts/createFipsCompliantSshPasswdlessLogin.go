package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	// Determine home directory and paths
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding home directory: %v\n", err)
		os.Exit(1)
	}
	sshDir := filepath.Join(homeDir, ".ssh")
	keyPath := filepath.Join(sshDir, "id_rsa_fips")
	configPath := filepath.Join(sshDir, "config")

	// Ensure ~/.ssh directory exists
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		if err := os.Mkdir(sshDir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating %s: %v\n", sshDir, err)
			os.Exit(1)
		}
	}

	// Generate a FIPS-compliant RSA key (2048-bit, no passphrase)
	fmt.Println("Generating FIPS-compliant SSH key at", keyPath)
	// Check if key already exists; if so, skip generation.
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		cmd := exec.Command("ssh-keygen", "-t", "rsa", "-b", "2048", "-f", keyPath, "-N", "")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "ssh-keygen failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Key already exists, skipping key generation.")
	}

	// Ask user which <user@host> they want to login to
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter target login (<user@host>): ")
	target, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed reading input: %v\n", err)
		os.Exit(1)
	}
	target = strings.TrimSpace(target)
	parts := strings.Split(target, "@")
	if len(parts) != 2 {
		fmt.Fprintf(os.Stderr, "Input must be in <user@host> format\n")
		os.Exit(1)
	}
	userName := parts[0]
	hostName := parts[1]

	// Run ssh-copy-id to copy the key to the target host
	fmt.Printf("Running ssh-copy-id for %s...\n", target)
	// Using -i flag to point to our generated public key
	sshCopyID := exec.Command("ssh-copy-id", "-i", keyPath+".pub", target)
	sshCopyID.Stdout = os.Stdout
	sshCopyID.Stderr = os.Stderr
	if err := sshCopyID.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-copy-id failed: %v\n", err)
		os.Exit(1)
	}

	// Append entry to ~/.ssh/config
	entry := fmt.Sprintf(`

Host %s
    HostName %s
    User %s
    IdentityFile %s
`, hostName, hostName, userName, keyPath)
	
	// Open the config file in append mode (or create if missing)
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening %s: %v\n", configPath, err)
		os.Exit(1)
	}
	defer f.Close()

	if _, err := f.WriteString(entry); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to %s: %v\n", configPath, err)
		os.Exit(1)
	}

	// Optionally, verify that the new entry exists by reading the file back.
	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", configPath, err)
		os.Exit(1)
	}
	if !strings.Contains(string(data), "Host "+hostName) {
		fmt.Fprintf(os.Stderr, "Verification failed: entry not found in config\n")
		os.Exit(1)
	}

	fmt.Println("finis")
}
