package systemd

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunSystemctl executes systemctl commands safely
// Migrated from cmd/backup/schedule.go runSystemctl
func RunSystemctl(rc *eos_io.RuntimeContext, args ...string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Validate systemctl is available
	logger.Debug("Assessing systemctl command availability")
	
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl not found: %w", err)
	}
	
	// INTERVENE - Execute the systemctl command
	logger.Debug("Executing systemctl command",
		zap.Strings("args", args))
	
	// First arg should be "systemctl"
	if len(args) == 0 || args[0] != "systemctl" {
		return fmt.Errorf("invalid systemctl command: %v", args)
	}
	
	if err := execute.RunSimple(rc.Ctx, args[0], args[1:]...); err != nil {
		return fmt.Errorf("systemctl %s failed: %w", strings.Join(args[1:], " "), err)
	}
	
	// EVALUATE - Command completed successfully
	logger.Debug("Systemctl command completed successfully",
		zap.Strings("args", args))
	
	return nil
}

// GetTimerStatus gets the status of a systemd timer
func GetTimerStatus(rc *eos_io.RuntimeContext, timerName string) (string, string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Prepare to check timer status
	logger.Debug("Assessing timer status requirements",
		zap.String("timer", timerName))
	
	// INTERVENE - Get timer status
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"show", timerName, "--property=ActiveState,NextElapseUSecRealtime"},
	})
	if err != nil {
		return "Unknown", "-", fmt.Errorf("getting timer status: %w", err)
	}
	
	// Parse output
	lines := strings.Split(strings.TrimSpace(output), "\n")
	status := "Unknown"
	nextRun := "-"
	
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		
		switch parts[0] {
		case "ActiveState":
			status = parts[1]
		case "NextElapseUSecRealtime":
			// TODO: Convert microseconds timestamp to human-readable format
			if parts[1] != "" && parts[1] != "0" {
				nextRun = "Scheduled"
			}
		}
	}
	
	// EVALUATE - Return parsed status
	logger.Debug("Timer status retrieved",
		zap.String("timer", timerName),
		zap.String("status", status),
		zap.String("next_run", nextRun))
	
	return status, nextRun, nil
}