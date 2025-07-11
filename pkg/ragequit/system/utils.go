package system

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"
)

// GetHostname returns the system hostname
// Migrated from cmd/ragequit/ragequit.go getHostname
func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// GetHomeDir returns the user's home directory
// Migrated from cmd/ragequit/ragequit.go getHomeDir
func GetHomeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	
	user, err := user.Current()
	if err != nil {
		return "/tmp"
	}
	return user.HomeDir
}

// FileExists checks if a file exists
// Migrated from cmd/ragequit/ragequit.go fileExists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// DirExists checks if a directory exists
// Migrated from cmd/ragequit/ragequit.go dirExists
func DirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// CommandExists checks if a command is available in PATH
// Migrated from cmd/ragequit/ragequit.go commandExists
func CommandExists(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

// IsExecutable checks if a file is executable
// Migrated from cmd/ragequit/ragequit.go isExecutable
func IsExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&0111 != 0
}

// ContainsString checks if a file contains a specific string
// Migrated from cmd/ragequit/ragequit.go containsString
func ContainsString(filePath, searchString string) bool {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	return strings.Contains(string(content), searchString)
}

// ReadFile reads a file and returns its content as string
// Migrated from cmd/ragequit/ragequit.go readFile
func ReadFile(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(content)
}

// RunCommandWithTimeout runs a command with a timeout
// Migrated from cmd/ragequit/ragequit.go runCommandWithTimeout
func RunCommandWithTimeout(command string, args []string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, command, args...)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "Command timed out"
		}
		return ""
	}
	
	return string(output)
}