// pkg/process/check.go
//
// Process management utilities - checking for running processes
// Pure business logic for process detection

package process

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunningProcessInfo contains information about running processes
type RunningProcessInfo struct {
	ProcessName    string
	PIDs           []string
	ExcludedPID    int  // PID to exclude from results (e.g., current process)
	OtherProcesses []string // PIDs excluding the excluded PID
}

// CheckRunningProcesses checks for running processes matching a pattern
// Returns information about matching processes, excluding the specified PID
func CheckRunningProcesses(rc *eos_io.RuntimeContext, processName string, excludePID int) (*RunningProcessInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	info := &RunningProcessInfo{
		ProcessName: processName,
		ExcludedPID: excludePID,
	}

	// Use pgrep to find processes matching the name
	cmd := exec.Command("pgrep", "-f", processName)
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

	// Parse PIDs
	processes := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, pidStr := range processes {
		pidStr = strings.TrimSpace(pidStr)
		if pidStr == "" {
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
