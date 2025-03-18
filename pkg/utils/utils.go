// pkg/utils/utils.go
package utils

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"io"

	"go.uber.org/zap"

	"eos/pkg/logger"
)

var log = logger.GetLogger() // Retrieve the globally initialized logger

//
//---------------------------- COMMAND EXECUTION ---------------------------- //
//

// Execute runs a command with separate arguments.
func Execute(command string, args ...string) error {
	log.Debug("Executing command", zap.String("command", command), zap.Strings("args", args))
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Error("Command execution failed", zap.String("command", command), zap.Strings("args", args), zap.Error(err))
	} else {
		log.Info("Command executed successfully", zap.String("command", command))
	}
	return err
}

// ExecuteShell runs a shell command with pipes (`| grep`).
func ExecuteShell(command string) error {
	log.Debug("Executing shell command", zap.String("command", command))
	cmd := exec.Command("bash", "-c", command) // Runs in shell mode
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err := cmd.Run()
	if err != nil {
		log.Error("Shell command execution failed", zap.String("command", command), zap.Error(err))
	} else {
		log.Info("Shell command executed successfully", zap.String("command", command))
	}
	return err
}

func ExecuteInDir(dir, command string, args ...string) error {
	log.Debug("Executing command in directory", zap.String("directory", dir), zap.String("command", command), zap.Strings("args", args))
	cmd := exec.Command(command, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Error("Command execution failed in directory", zap.String("directory", dir), zap.String("command", command), zap.Strings("args", args), zap.Error(err))
	} else {
		log.Info("Command executed successfully in directory", zap.String("directory", dir), zap.String("command", command))
	}
	return err
}

//
//---------------------------- CRYPTO, HASHING, SECRETS ---------------------------- //
//

// HashString computes and returns the SHA256 hash of the provided string.
func HashString(s string) string {
	log.Debug("Computing SHA256 hash", zap.String("input", s))
	hash := sha256.Sum256([]byte(s))
	hashStr := hex.EncodeToString(hash[:])
	log.Debug("Computed SHA256 hash", zap.String("hash", hashStr))
	return hashStr
}

// generatePassword creates a random alphanumeric password of the given length.
func GeneratePassword(length int) (string, error) {
	// Generate random bytes. Since hex encoding doubles the length, we need length/2 bytes.
	bytes := make([]byte, length/2)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	// Encode to hex and trim to required length.
	return hex.EncodeToString(bytes)[:length], nil
}


//
//---------------------------- LOGGING ---------------------------- //
//

// monitorVaultLogs tails the log file and prints new lines to STDOUT.
// It returns when it sees a line containing the specified marker or when the context is done.
func MonitorVaultLogs(ctx context.Context, logFilePath, marker string) error {
	file, err := os.Open(logFilePath)
	if err != nil {
		log.Error("Failed to open log file for monitoring", zap.String("logFilePath", logFilePath), zap.Error(err))
		return fmt.Errorf("failed to open log file for monitoring: %w", err)
	}
	defer file.Close()

	// Seek to the end of the file so we only see new log lines.
	_, err = file.Seek(0, io.SeekEnd)
	if err != nil {
		log.Error("Failed to seek log file", zap.String("logFilePath", logFilePath), zap.Error(err))
		return fmt.Errorf("failed to seek log file: %w", err)
	}

	scanner := bufio.NewScanner(file)
	for {
		select {
		case <-ctx.Done():
			log.Warn("Timeout reached while waiting for Vault to start")
			return fmt.Errorf("timeout reached while waiting for Vault to start")
		default:
			if scanner.Scan() {
				line := scanner.Text()
				fmt.Println(line) // Print the log line to terminal
				log.Debug("Vault Log Line", zap.String("logLine", line))
				if strings.Contains(line, marker) {
					log.Info("Vault marker found, exiting log monitor", zap.String("marker", marker))
					return nil
				}
			} else {
				time.Sleep(500 * time.Millisecond) // No new line, wait and try again
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
	log.Info("Retrieving internal hostname")
	hostname, err := os.Hostname()
	if err != nil {
		log.Error("Unable to retrieve hostname, defaulting to localhost", zap.Error(err))
		return "localhost"
	}
	log.Info("Retrieved hostname", zap.String("hostname", hostname))
	return hostname
}


//
//---------------------------- ERROR HANDLING ---------------------------- //
//

// HandleError logs an error and optionally exits the program
func HandleError(err error, message string, exit bool) {
	if err != nil {
		log.Error(message, zap.Error(err))
		if exit {
			log.Fatal("Exiting program due to error", zap.String("message", message))
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
	log.Info("Checking if user has sudo privileges")
	cmd := exec.Command("sudo", "-n", "true") // Non-interactive sudo check
	err := cmd.Run()
	if err != nil {
		log.Warn("User does not have sudo privileges", zap.Error(err))
		return false
	}
	log.Info("User has sudo privileges")
	return true
}


//
//---------------------------- YAML ---------------------------- //
//


// Recursive function to process and print nested YAML structures
func ProcessMap(data map[string]interface{}, indent string) {
	log.Debug("Processing YAML map")
	for key, value := range data {
		switch v := value.(type) {
		case map[string]interface{}:
			fmt.Printf("%s%s:\n", indent, key)
			ProcessMap(v, indent+"  ")
		case []interface{}:
			fmt.Printf("%s%s:\n", indent, key)
			for _, item := range v {
				if itemMap, ok := item.(map[string]interface{}); ok {
					ProcessMap(itemMap, indent+"  ")
				} else {
					fmt.Printf("%s  - %v\n", indent, item)
				}
			}
		default:
			fmt.Printf("%s%s: %v\n", indent, key, v)
		}
	}
	log.Debug("Completed processing YAML map")
}
