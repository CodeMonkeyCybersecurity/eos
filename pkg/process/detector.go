package process

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
)

// ProcessInfo contains information about a running process
type ProcessInfo struct {
	PID     int
	Name    string
	Command string
}

// FindProcesses finds all processes matching the given pattern
// Returns empty slice if no processes found (not an error condition)
func FindProcesses(ctx context.Context, pattern string) ([]ProcessInfo, error) {
	// Use ps with specific format to avoid pgrep exit code issues
	output, err := execute.Run(ctx, execute.Options{
		Command: "ps",
		Args:    []string{"aux"},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	if err != nil {
		// ps command failed - this is an actual error
		return nil, err
	}

	processes := []ProcessInfo{}
	lines := strings.Split(output, "\n")

	// Skip header line
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		// Check if line contains our pattern
		if strings.Contains(line, pattern) {
			// Parse the line
			fields := strings.Fields(line)
			// SECURITY P0 #2: Safe array bounds - need >10 elements to access fields[10]
			// Fields: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND...
			// Index:    0   1    2    3   4   5   6    7     8    9      10
			if len(fields) > 10 { // Changed from >= 11 to > 10 for clarity
				if pid, err := strconv.Atoi(fields[1]); err == nil {
					// Skip our own grep/ps processes
					cmdLine := strings.Join(fields[10:], " ")
					if strings.Contains(cmdLine, "ps aux") || strings.Contains(cmdLine, "grep") {
						continue
					}

					processes = append(processes, ProcessInfo{
						PID:     pid,
						Name:    fields[10], // Safe - len > 10 means index 10 is valid
						Command: cmdLine,
					})
				}
			}
		}
	}

	return processes, nil
}

// IsProcessRunning checks if a process matching the pattern is running
// Returns false if no process found (not an error)
func IsProcessRunning(ctx context.Context, pattern string) (bool, error) {
	processes, err := FindProcesses(ctx, pattern)
	if err != nil {
		return false, err
	}
	return len(processes) > 0, nil
}

// KillProcesses gracefully terminates and then force kills processes matching pattern
// Returns number of processes killed
func KillProcesses(ctx context.Context, pattern string) (int, error) {
	processes, err := FindProcesses(ctx, pattern)
	if err != nil {
		return 0, err
	}

	if len(processes) == 0 {
		return 0, nil // No processes to kill
	}

	// Collect PIDs
	pids := []string{}
	for _, proc := range processes {
		pids = append(pids, strconv.Itoa(proc.PID))
	}

	// First try SIGTERM
	_, _ = execute.Run(ctx, execute.Options{
		Command: "kill",
		Args:    append([]string{"-TERM"}, pids...),
		Timeout: 5 * time.Second,
	})

	// Wait for graceful shutdown
	// SECURITY P0 #1: Use context-aware sleep to respect cancellation
	select {
	case <-time.After(2 * time.Second):
		// Continue after graceful shutdown wait
	case <-ctx.Done():
		return 0, fmt.Errorf("process termination cancelled during graceful wait: %w", ctx.Err())
	}

	// Check if any still running
	stillRunning, _ := FindProcesses(ctx, pattern)
	if len(stillRunning) > 0 {
		// Force kill remaining
		remainingPids := []string{}
		for _, proc := range stillRunning {
			remainingPids = append(remainingPids, strconv.Itoa(proc.PID))
		}

		_, _ = execute.Run(ctx, execute.Options{
			Command: "kill",
			Args:    append([]string{"-KILL"}, remainingPids...),
			Timeout: 5 * time.Second,
		})
	}

	return len(processes), nil
}

// ServiceStatus represents the status of a systemd service
type ServiceStatus struct {
	Name      string
	IsActive  bool
	IsEnabled bool
	State     string // active, inactive, failed, etc.
	SubState  string // running, dead, exited, etc.
}

// GetServiceStatus checks the status of a systemd service
// Returns nil if service doesn't exist
func GetServiceStatus(ctx context.Context, serviceName string) (*ServiceStatus, error) {
	// Check if service unit exists
	listOutput, err := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-unit-files", "--no-pager", serviceName},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	if err != nil || listOutput == "" || !strings.Contains(listOutput, serviceName) {
		return nil, nil // Service doesn't exist
	}

	status := &ServiceStatus{
		Name: serviceName,
	}

	// Check if active
	activeOutput, _ := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", serviceName},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	status.State = strings.TrimSpace(activeOutput)
	status.IsActive = status.State == "active"

	// Check if enabled
	enabledOutput, _ := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-enabled", serviceName},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	enabledState := strings.TrimSpace(enabledOutput)
	status.IsEnabled = enabledState == "enabled"

	// Get detailed status
	if showOutput, err := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"show", serviceName, "--property=SubState"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil {
		if parts := strings.Split(showOutput, "="); len(parts) == 2 {
			status.SubState = strings.TrimSpace(parts[1])
		}
	}

	return status, nil
}

// IsAPIAccessible checks if a service API is accessible
// This is a generic check that can be extended for specific services
func IsAPIAccessible(ctx context.Context, checkCommand string, checkArgs []string) bool {
	// Short timeout for API checks
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	_, err := execute.Run(ctx, execute.Options{
		Command: checkCommand,
		Args:    checkArgs,
		Capture: true,
	})

	return err == nil
}
