// pkg/process/check.go
//
// Process management utilities - checking for running processes
// Pure business logic for process detection

package process

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunningProcessInfo contains information about running processes
type RunningProcessInfo struct {
	ProcessName    string
	PIDs           []string
	ExcludedPID    int      // PID to exclude from results (e.g., current process)
	OtherProcesses []string // PIDs excluding the excluded PID
}

// P0 FIX (Adversarial #3): Platform-specific binary path detection
// getProcessBinaryPath returns the full path to a process's binary
// RATIONALE: /proc/$PID/exe only exists on Linux. macOS and BSD use different mechanisms.
func getProcessBinaryPath(pid string) (string, error) {
	switch runtime.GOOS {
	case "linux":
		// Linux: Read /proc/$PID/exe symlink
		exePath := fmt.Sprintf("/proc/%s/exe", pid)
		target, err := os.Readlink(exePath)
		if err != nil {
			return "", fmt.Errorf("cannot read /proc/%s/exe: %w", pid, err)
		}
		return target, nil

	case "darwin":
		// macOS: Use lsof to get binary path
		// lsof -p $PID -Fn | grep ^ntxt | head -1
		cmd := exec.Command("lsof", "-p", pid, "-Fn")
		output, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("lsof failed for PID %s: %w", pid, err)
		}

		// Parse lsof output for txt (binary) entry
		// Format: n/path/to/binary
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			// Look for the txt file (the actual binary)
			if strings.HasPrefix(line, "ntxt") || strings.HasPrefix(line, "n/") {
				// Skip the 'n' prefix
				if len(line) > 1 {
					path := line[1:]
					// Return first executable path found
					if strings.Contains(path, "/") {
						return path, nil
					}
				}
			}
		}
		return "", fmt.Errorf("could not determine binary path from lsof output for PID %s", pid)

	case "freebsd", "openbsd", "netbsd":
		// BSD: Use procstat on FreeBSD, or fall back to ps
		cmd := exec.Command("procstat", "binary", pid)
		output, err := cmd.Output()
		if err != nil {
			// Fall back to ps if procstat not available
			cmd = exec.Command("ps", "-p", pid, "-o", "comm=")
			output, err = cmd.Output()
			if err != nil {
				return "", fmt.Errorf("cannot determine binary path on BSD for PID %s: %w", pid, err)
			}
		}
		path := strings.TrimSpace(string(output))
		if path == "" {
			return "", fmt.Errorf("empty binary path from procstat/ps for PID %s", pid)
		}
		return path, nil

	default:
		// Unsupported platform - fall back to ps which works everywhere
		// but may give just the command name, not full path
		cmd := exec.Command("ps", "-p", pid, "-o", "comm=")
		output, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("ps failed for PID %s on %s: %w", pid, runtime.GOOS, err)
		}
		path := strings.TrimSpace(string(output))
		if path == "" {
			return "", fmt.Errorf("empty command from ps for PID %s", pid)
		}
		// ps may return just command name, not full path - warn about this
		return path, nil
	}
}

// CheckRunningProcesses checks for running processes matching a pattern
// Returns information about matching processes, excluding the specified PID
// P1 FIX: Uses exact binary name matching with verification to prevent false positives
func CheckRunningProcesses(rc *eos_io.RuntimeContext, processName string, excludePID int) (*RunningProcessInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	info := &RunningProcessInfo{
		ProcessName: processName,
		ExcludedPID: excludePID,
	}

	// P1 FIX: Use pgrep -x for EXACT binary name match (not substring)
	// This prevents false positives like "videos.txt" matching "eos"
	cmd := exec.Command("pgrep", "-x", processName)
	output, err := cmd.Output()

	// pgrep returns exit code 1 if no processes found (not an error)
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.ExitCode() == 1 {
				// No processes found
				logger.Debug("No running processes found",
					zap.String("process_name", processName))
				return info, nil
			}
		}
		// Real error
		return nil, fmt.Errorf("failed to check for running processes: %w", err)
	}

	if len(output) == 0 {
		return info, nil
	}

	// Parse PIDs and verify each one is actually the binary we're looking for
	processes := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, pidStr := range processes {
		pidStr = strings.TrimSpace(pidStr)
		if pidStr == "" {
			continue
		}

		// P1 FIX: Verify this PID is actually running our binary
		// P0 FIX (Adversarial #3): Use platform-specific binary path detection
		target, err := getProcessBinaryPath(pidStr)
		if err != nil {
			// Process may have exited, permission denied, or platform issue
			logger.Debug("Cannot determine process binary path (may have exited)",
				zap.String("pid", pidStr),
				zap.String("platform", runtime.GOOS),
				zap.Error(err))
			continue
		}

		// Extract binary name from full path (e.g., /usr/local/bin/eos -> eos)
		binaryName := target
		if lastSlash := strings.LastIndex(target, "/"); lastSlash != -1 {
			binaryName = target[lastSlash+1:]
		}

		// Only include if binary name matches exactly
		if binaryName != processName {
			logger.Debug("PID binary name mismatch (false positive from pgrep)",
				zap.String("pid", pidStr),
				zap.String("expected", processName),
				zap.String("actual", binaryName))
			continue
		}

		info.PIDs = append(info.PIDs, pidStr)

		// Check if this is the excluded PID
		if pidStr != fmt.Sprintf("%d", excludePID) {
			info.OtherProcesses = append(info.OtherProcesses, pidStr)
		}
	}

	if len(info.OtherProcesses) > 0 {
		logger.Debug("Found running processes",
			zap.String("process_name", processName),
			zap.Strings("pids", info.OtherProcesses),
			zap.Int("excluded_pid", excludePID))
	}

	return info, nil
}

// WarnAboutRunningProcesses logs a warning if other processes are running
// This is useful for operations like self-update where running processes
// will continue using the old binary
func WarnAboutRunningProcesses(rc *eos_io.RuntimeContext, processName string) error {
	currentPID := os.Getpid()
	info, err := CheckRunningProcesses(rc, processName, currentPID)
	if err != nil {
		return err
	}

	if len(info.OtherProcesses) > 0 {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Warn("Other processes are running",
			zap.String("process", processName),
			zap.Strings("pids", info.OtherProcesses),
			zap.String("warning", "They will continue using the old binary until restarted"))
	}

	return nil
}
