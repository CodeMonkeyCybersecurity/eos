// pkg/interaction/tty.go
package interaction

import (
	"os"
	"runtime"
	"strings"
)

// IsTTY checks if running in an interactive terminal with multiple fallbacks
// Handles edge cases: VS Code terminals, tmux/screen, Docker, WSL
func IsTTY() bool {
	// Check 1: stdin is a character device
	fileInfo, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	if (fileInfo.Mode() & os.ModeCharDevice) == 0 {
		return false
	}

	// Check 2: TERM environment variable exists and is not "dumb"
	term := os.Getenv("TERM")
	if term == "" || term == "dumb" {
		return false
	}

	// Check 3: Platform-specific checks
	if runtime.GOOS == "windows" {
		// Windows: check for ConEmu, Windows Terminal, or MinTTY
		return isWindowsTTY()
	}

	// Check 4: Not in CI/CD environment
	if isCIEnvironment() {
		return false
	}

	return true
}

// isWindowsTTY performs Windows-specific TTY detection
func isWindowsTTY() bool {
	// Check for common Windows terminal emulators
	termProgram := os.Getenv("TERM_PROGRAM")
	if termProgram != "" {
		return true // VS Code, Windows Terminal, etc.
	}

	// Check for ConEmu
	if os.Getenv("ConEmuPID") != "" {
		return true
	}

	// Check for MinTTY (Git Bash)
	if strings.Contains(os.Getenv("SHELL"), "bash") {
		return true
	}

	return false
}

// isCIEnvironment detects if running in CI/CD
func isCIEnvironment() bool {
	ciEnvVars := []string{
		"CI", "CONTINUOUS_INTEGRATION",
		"GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI",
		"TRAVIS", "JENKINS_HOME", "BUILDKITE",
	}

	for _, envVar := range ciEnvVars {
		if os.Getenv(envVar) != "" {
			return true
		}
	}

	return false
}
