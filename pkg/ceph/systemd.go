// pkg/ceph/systemd.go
package ceph

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckSystemdUnits checks Ceph systemd unit files and their states
func CheckSystemdUnits(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	logger.Info("Checking systemd units...")

	// Get detailed status of critical Ceph units
	criticalUnits := []string{"ceph.target", "ceph-mon.target", "ceph-mgr.target", "ceph-osd.target"}

	// Track specific instance units separately to detect missing daemons
	monInstances := []string{}
	mgrInstances := []string{}
	osdInstances := []string{}
	seenUnits := make(map[string]bool) // Track to avoid duplicates

	// Mark base targets as seen
	for _, unit := range criticalUnits {
		seenUnits[unit] = true
	}

	// Check if any specific mon/mgr/osd instances exist
	cmd := exec.Command("systemctl", "list-units", "ceph-mon@*", "ceph-mgr@*", "ceph-osd@*", "--all", "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		logger.Warn("Failed to list systemd units", zap.Error(err))
	} else {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Only process lines with Ceph daemon instances
			if !strings.Contains(line, "ceph-mon@") &&
				!strings.Contains(line, "ceph-mgr@") &&
				!strings.Contains(line, "ceph-osd@") {
				continue
			}

			// Extract just the unit name (first field)
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}

			unitName := fields[0]

			// Skip if already seen
			if seenUnits[unitName] {
				continue
			}

			seenUnits[unitName] = true
			criticalUnits = append(criticalUnits, unitName)

			// Track by daemon type
			if strings.Contains(unitName, "ceph-mon@") {
				monInstances = append(monInstances, unitName)
			} else if strings.Contains(unitName, "ceph-mgr@") {
				mgrInstances = append(mgrInstances, unitName)
			} else if strings.Contains(unitName, "ceph-osd@") {
				osdInstances = append(osdInstances, unitName)
			}
		}
	}

	// Check status of each unit
	activeCount := 0
	inactiveCount := 0
	failedCount := 0

	logger.Info("Systemd unit status:")
	for _, unit := range criticalUnits {
		cmd = exec.Command("systemctl", "is-active", unit)
		output, _ := cmd.Output()
		status := strings.TrimSpace(string(output))

		cmd = exec.Command("systemctl", "is-enabled", unit)
		enabledOutput, _ := cmd.Output()
		enabled := strings.TrimSpace(string(enabledOutput))

		var symbol string
		var statusMsg string

		switch status {
		case "active":
			symbol = "✓"
			statusMsg = "active"
			activeCount++
		case "inactive":
			symbol = "○"
			statusMsg = "inactive"
			inactiveCount++
		case "failed":
			symbol = "✗"
			statusMsg = "FAILED"
			failedCount++
		default:
			symbol = "?"
			statusMsg = status
		}

		// Show enabled status
		if enabled == "enabled" {
			logger.Info(fmt.Sprintf("  %s %-30s %s (enabled)", symbol, unit, statusMsg))
		} else {
			logger.Info(fmt.Sprintf("  %s %-30s %s (%s)", symbol, unit, statusMsg, enabled))
		}

		// If failed, show why
		if status == "failed" {
			cmd = exec.Command("systemctl", "status", unit, "--no-pager", "-n", "3")
			if output, err := cmd.Output(); err == nil {
				if verbose {
					logger.Error(fmt.Sprintf("    Failure details for %s:", unit))
					for _, line := range strings.Split(string(output), "\n") {
						if strings.TrimSpace(line) != "" {
							logger.Error("      " + line)
						}
					}
				}
			}
		}
	}

	// Summary
	logger.Info("")
	logger.Info(fmt.Sprintf("Summary: %d active, %d inactive, %d failed", activeCount, inactiveCount, failedCount))

	// Check for critical missing daemon instances
	logger.Info("")
	if len(monInstances) == 0 {
		logger.Error("❌ CRITICAL: No ceph-mon instances found in systemd!")
		logger.Info("  → Expected format: ceph-mon@<hostname>.service")
		logger.Info("  → Check if mon was ever initialized on this host")
		logger.Info("  → Try: systemctl list-unit-files | grep ceph-mon")

		// Try to get more context from journal
		if verbose {
			logger.Info("")
			logger.Info("Checking journal for mon daemon errors...")

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			journalCmd := exec.CommandContext(ctx, "journalctl", "-u", "ceph-mon@*", "-n", "20", "--no-pager")
			output, err := journalCmd.Output()
			if err != nil {
				if ctx.Err() == context.DeadlineExceeded {
					logger.Warn("  → Journal query timed out after 10 seconds")
				} else {
					logger.Warn("  → Could not access journal logs", zap.Error(err))
				}
			} else {
				outputStr := strings.TrimSpace(string(output))
				if outputStr != "" && !strings.Contains(outputStr, "No entries") {
					logger.Info("Recent mon journal entries:")
					for _, line := range strings.Split(outputStr, "\n") {
						logger.Info("  " + line)
					}
				} else {
					logger.Info("  → No journal entries found for ceph-mon")
				}
			}
		}
	} else {
		logger.Info(fmt.Sprintf("Found %d mon instance(s): %v", len(monInstances), monInstances))
	}

	if len(mgrInstances) == 0 {
		logger.Warn("⚠️  No ceph-mgr instances found in systemd")
	} else {
		logger.Info(fmt.Sprintf("Found %d mgr instance(s): %v", len(mgrInstances), mgrInstances))
	}

	if len(osdInstances) == 0 {
		logger.Warn("⚠️  No ceph-osd instances found in systemd")
		logger.Info("  → OSDs must be created with: ceph-volume lvm create")
	} else {
		logger.Info(fmt.Sprintf("Found %d osd instance(s): %v", len(osdInstances), osdInstances))
	}

	if failedCount > 0 {
		logger.Error("❌ Some units have failed - check logs with: journalctl -u <unit-name> -xe")
		return DiagnosticResult{
			CheckName: "Systemd Units",
			Passed:    false,
			Error:     fmt.Errorf("%d systemd units failed", failedCount),
		}
	}

	if activeCount == 0 {
		logger.Warn("⚠️  No active Ceph units")
		logger.Info("  → Try: systemctl start ceph.target")
		return DiagnosticResult{
			CheckName: "Systemd Units",
			Passed:    false,
			Error:     fmt.Errorf("no active ceph units"),
		}
	}

	if len(monInstances) == 0 {
		return DiagnosticResult{
			CheckName: "Systemd Units",
			Passed:    false,
			Error:     fmt.Errorf("no monitor instances configured"),
		}
	}

	return DiagnosticResult{
		CheckName: "Systemd Units",
		Passed:    true,
	}
}
