package utils

import (
	"log"
	"fmt"
	"os"
	"os/exec"
	"context"
	"bufio"
	"strings"
	"time"
	"crypto/sha256"
	"encoding/hex"

)


//
//---------------------------- COMMAND EXECUTION ---------------------------- //
//

// Execute runs a command with separate arguments.
func Execute(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

// ExecuteShell runs a shell command with pipes (`| grep`).
func ExecuteShell(command string) error {
	cmd := exec.Command("bash", "-c", command) // Runs in shell mode
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

//
//---------------------------- CRYPTO AND HASHING ---------------------------- //
//

// HashString computes and returns the SHA256 hash of the provided string.
func HashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}


//
//---------------------------- LOGGING ---------------------------- //
//

// monitorVaultLogs tails the log file and prints new lines to STDOUT.
// It returns when it sees a line containing the specified marker or when the context is done.
func MonitorVaultLogs(ctx context.Context, logFilePath, marker string) error {
	file, err := os.Open(logFilePath)
	if err != nil {
		return fmt.Errorf("failed to open log file for monitoring: %w", err)
	}
	defer file.Close()

	// Seek to the end of the file so we only see new log lines.
	_, err = file.Seek(0, os.SEEK_END)
	if err != nil {
		return fmt.Errorf("failed to seek log file: %w", err)
	}

	scanner := bufio.NewScanner(file)
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout reached while waiting for Vault to start")
		default:
			// Read new lines if available.
			if scanner.Scan() {
				line := scanner.Text()
				fmt.Println(line) // Print the log line to terminal.
				if strings.Contains(line, marker) {
					return nil
				}
			} else {
				// No new line; wait briefly and try again.
				time.Sleep(500 * time.Millisecond)
			}
		}
	}
}

//
//---------------------------- HOSTNAME ---------------------------- //
//

// GetInternalHostname returns the machine's hostname.
// If os.Hostname() fails, it logs the error and returns "localhost".
func GetInternalHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Unable to retrieve hostname, defaulting to localhost: %v", err)
		return "localhost"
	}
	return hostname
}


//
//---------------------------- ERROR HANDLING ---------------------------- //
//

// HandleError logs an error and optionally exits the program
func HandleError(err error, message string, exit bool) {
	if err != nil {
		log.Printf("[ERROR] %s: %v\n", message, err)
		if exit {
			fmt.Println("Exiting program due to error.")
			os.Exit(1)
		}
	}
}

// WithErrorHandling wraps a function with error handling
func WithErrorHandling(fn func() error) {
	err := fn()
	if err != nil {
		HandleError(err, "An error occurred", true)
	}
}


//
//---------------------------- PERMISSIONS ---------------------------- //
//

// CheckSudo checks if the current user has sudo privileges
func CheckSudo() bool {
	cmd := exec.Command("sudo", "-n", "true") // Non-interactive sudo check
	err := cmd.Run()
	return err == nil
}


//
//---------------------------- YAML ---------------------------- //
//


// Recursive function to process and print nested YAML structures
func ProcessMap(data map[string]interface{}, indent string) {
	for key, value := range data {
		switch v := value.(type) {
		case map[string]interface{}:
			// If the value is a nested map, call processMap recursively
			fmt.Printf("%s%s:\n", indent, key)
			ProcessMap(v, indent+"  ")
		case []interface{}:
			// If the value is a slice, process each element
			fmt.Printf("%s%s:\n", indent, key)
			for _, item := range v {
				if itemMap, ok := item.(map[string]interface{}); ok {
					ProcessMap(itemMap, indent+"  ")
				} else {
					fmt.Printf("%s  - %v\n", indent, item)
				}
			}
		default:
			// Print scalar values
			fmt.Printf("%s%s: %v\n", indent, key, v)
		}
	}
}
