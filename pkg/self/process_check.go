// pkg/self/process_check.go
//
// Running process detection and consent for safe self-update
// HUMAN-CENTRIC: Prevents replacing binary in use, guides user through safe shutdown

package self

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/process"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// RunningProcessInfo contains information about a running eos process
type RunningProcessInfo struct {
	PID     int
	Command string
	User    string
	IsSelf  bool // True if this is the current process
}

// checkRunningEosProcesses checks for other running eos processes using existing process package
// SECURITY CRITICAL: Prevents race conditions during self-update
func checkRunningEosProcesses(rc *eos_io.RuntimeContext) ([]RunningProcessInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking for running eos processes")

	currentPID := os.Getpid()

	// Use existing process.CheckRunningProcesses to find all eos processes
	processInfo, err := process.CheckRunningProcesses(rc, "eos", currentPID)
	if err != nil {
		return nil, fmt.Errorf("failed to check for running processes: %w", err)
	}

	// If no other processes, return empty list
	if len(processInfo.OtherProcesses) == 0 {
		logger.Debug("No other running eos processes found")
		return nil, nil
	}

	// Convert PIDs to RunningProcessInfo structures
	var runningProcesses []RunningProcessInfo
	for _, pidStr := range processInfo.OtherProcesses {
		// For now, we just have PIDs - getting full command info requires additional parsing
		runningProcesses = append(runningProcesses, RunningProcessInfo{
			PID:     mustAtoi(pidStr),
			Command: "eos (details not available)", // pgrep doesn't give us full command
			User:    "unknown",                      // pgrep doesn't give us user
			IsSelf:  false,
		})
	}

	logger.Warn("Found running eos processes",
		zap.Int("count", len(runningProcesses)))

	return runningProcesses, nil
}

// mustAtoi converts string to int, returns 0 on error
func mustAtoi(s string) int {
	var result int
	fmt.Sscanf(s, "%d", &result)
	return result
}

// HandleRunningProcesses checks for running processes and asks for user consent
// HUMAN-CENTRIC: Explains the risk and guides user through safe shutdown
func HandleRunningProcesses(rc *eos_io.RuntimeContext, binaryPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check for running processes
	runningProcesses, err := checkRunningEosProcesses(rc)
	if err != nil {
		return fmt.Errorf("failed to check running processes: %w", err)
	}

	// If no running processes, we're safe to proceed
	if len(runningProcesses) == 0 {
		logger.Debug("No running eos processes - safe to update")
		return nil
	}

	// Found running processes - need user consent
	logger.Warn("Running eos processes detected",
		zap.Int("count", len(runningProcesses)))

	// Check if interactive
	isInteractive := term.IsTerminal(int(os.Stdin.Fd()))
	if !isInteractive {
		// Non-interactive mode - fail with clear error
		errorMsg := fmt.Sprintf("CANNOT UPDATE: %d eos process(es) currently running\n\n", len(runningProcesses))
		errorMsg += "Running processes:\n"
		for i, proc := range runningProcesses {
			errorMsg += fmt.Sprintf("  %d. PID %d (user: %s)\n", i+1, proc.PID, proc.User)
			errorMsg += fmt.Sprintf("     Command: %s\n", proc.Command)
		}
		errorMsg += "\nTo update eos:\n"
		errorMsg += "  1. Stop all running eos processes\n"
		errorMsg += "  2. Re-run: eos self update\n\n"
		errorMsg += "IMPORTANT: Updating while processes are running can cause:\n"
		errorMsg += "  • Incomplete operations\n"
		errorMsg += "  • Corrupted state\n"
		errorMsg += "  • Binary replaced mid-execution\n"

		return fmt.Errorf("%s", errorMsg)
	}

	// Interactive mode - explain risk and ask for consent
	fmt.Println("\n⚠️  WARNING: Running eos processes detected")
	fmt.Println("")
	fmt.Printf("Found %d eos process(es) currently running:\n", len(runningProcesses))
	fmt.Println("")

	for i, proc := range runningProcesses {
		fmt.Printf("  %d. PID %d (user: %s)\n", i+1, proc.PID, proc.User)
		fmt.Printf("     %s\n", proc.Command)
	}

	fmt.Println("")
	fmt.Println("RISK:")
	fmt.Println("  • Updating the binary while it's in use can cause unexpected behavior")
	fmt.Println("  • Running operations may fail or produce incorrect results")
	fmt.Println("  • Binary may be replaced mid-execution")
	fmt.Println("")
	fmt.Println("RECOMMENDED:")
	fmt.Println("  1. Stop all running eos processes")
	fmt.Println("  2. Wait for operations to complete")
	fmt.Println("  3. Then re-run: eos self update")
	fmt.Println("")
	fmt.Println("To stop processes:")
	for _, proc := range runningProcesses {
		fmt.Printf("  kill %d    # Stop PID %d\n", proc.PID, proc.PID)
	}
	fmt.Println("")

	// Ask for consent to proceed anyway
	confirmed, err := interaction.PromptYesNoSafe(rc,
		"Continue with update anyway? (NOT RECOMMENDED)",
		false) // Default to No for safety

	if err != nil {
		return fmt.Errorf("failed to get user consent: %w", err)
	}

	if !confirmed {
		logger.Info("User declined to update with running processes - SAFE CHOICE")
		return fmt.Errorf("update cancelled - %d eos process(es) still running\n\n"+
			"This is the SAFE choice. Stop running processes and try again.",
			len(runningProcesses))
	}

	// User chose to proceed despite warning
	logger.Warn("User consented to update with running processes - RISKY",
		zap.Int("process_count", len(runningProcesses)))

	fmt.Println("\n⚠️  Proceeding with update despite running processes...")
	fmt.Println("IMPORTANT: If the update fails, those processes may be affected.")
	fmt.Println("")

	return nil
}
