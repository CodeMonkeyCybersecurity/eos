// pkg/ceph/processes.go
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

// CheckProcesses checks if any Ceph processes are running
func CheckProcesses(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	logger.Info("Checking for Ceph processes...")

	// Use ps with specific format for reliable parsing
	// Format: PID,COMMAND (no spaces, easier to parse)
	cmd := exec.Command("ps", "-eo", "pid,comm,args")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to list processes", zap.Error(err))
		return DiagnosticResult{
			CheckName: "Processes",
			Passed:    false,
			Error:     fmt.Errorf("cannot list processes: %w", err),
		}
	}

	// Categorize processes by type
	processCounts := map[string]int{
		"ceph-mon":    0,
		"ceph-mgr":    0,
		"ceph-osd":    0,
		"ceph-mds":    0,
		"ceph-crash":  0,
		"ceph-volume": 0,
		"radosgw":     0,
		"rbd-mirror":  0,
		"other":       0,
	}

	cephProcesses := []string{}
	otherProcesses := []string{} // Track what "other" processes are
	lines := strings.Split(string(output), "\n")

	for i, line := range lines {
		if i == 0 {
			continue // Skip header line
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse: PID COMMAND ARGS
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		command := fields[1]
		fullLine := strings.Join(fields[2:], " ")

		// Only match actual Ceph daemon processes (not scripts/logs mentioning ceph)
		// Check the command name itself, not arguments
		if !strings.HasPrefix(command, "ceph-") &&
		   command != "radosgw" &&
		   command != "rbd-mirror" &&
		   !strings.Contains(fullLine, "/usr/bin/ceph-") &&
		   !strings.Contains(fullLine, "/usr/local/bin/ceph-") {
			continue
		}

		// Skip our own process and grep
		if strings.Contains(fullLine, "ps -eo") || strings.Contains(command, "grep") {
			continue
		}

		cephProcesses = append(cephProcesses, strings.TrimSpace(line))

		// Count by type using command name (more reliable)
		switch {
		case strings.HasPrefix(command, "ceph-mon") || strings.Contains(fullLine, "ceph-mon"):
			processCounts["ceph-mon"]++
		case strings.HasPrefix(command, "ceph-mgr") || strings.Contains(fullLine, "ceph-mgr"):
			processCounts["ceph-mgr"]++
		case strings.HasPrefix(command, "ceph-osd") || strings.Contains(fullLine, "ceph-osd"):
			processCounts["ceph-osd"]++
		case strings.HasPrefix(command, "ceph-mds") || strings.Contains(fullLine, "ceph-mds"):
			processCounts["ceph-mds"]++
		case strings.HasPrefix(command, "ceph-crash") || strings.Contains(fullLine, "ceph-crash"):
			processCounts["ceph-crash"]++
		case strings.HasPrefix(command, "ceph-volume") || strings.Contains(fullLine, "ceph-volume"):
			processCounts["ceph-volume"]++
		case command == "radosgw" || strings.Contains(fullLine, "radosgw"):
			processCounts["radosgw"]++
		case command == "rbd-mirror" || strings.Contains(fullLine, "rbd-mirror"):
			processCounts["rbd-mirror"]++
		default:
			processCounts["other"]++
			// Track what these "other" processes are
			if command != "" {
				otherProcesses = append(otherProcesses, command)
			}
		}
	}

	if len(cephProcesses) == 0 {
		logger.Error("❌ No Ceph processes running")
		logger.Info("  → Ceph cluster is not started")
		logger.Info("  → Try: systemctl start ceph.target")
		return DiagnosticResult{
			CheckName: "Processes",
			Passed:    false,
			Error:     fmt.Errorf("no ceph processes found"),
		}
	}

	// Show breakdown by daemon type
	logger.Info(fmt.Sprintf("Found %d Ceph processes:", len(cephProcesses)))

	// Show critical daemons first
	criticalDaemons := []string{"ceph-mon", "ceph-mgr"}
	for _, daemonType := range criticalDaemons {
		count := processCounts[daemonType]
		if count > 0 {
			logger.Info(fmt.Sprintf("  ✓ %s: %d process(es) running", daemonType, count))
		}
	}

	// Show other daemon types
	otherDaemons := []string{"ceph-osd", "ceph-mds", "radosgw", "rbd-mirror", "ceph-volume", "ceph-crash"}
	for _, daemonType := range otherDaemons {
		count := processCounts[daemonType]
		if count > 0 {
			logger.Info(fmt.Sprintf("    %s: %d process(es)", daemonType, count))
		}
	}

	// Show "other" processes with details
	if processCounts["other"] > 0 {
		logger.Info(fmt.Sprintf("    other: %d process(es)", processCounts["other"]))
		if verbose && len(otherProcesses) > 0 {
			logger.Info("      Identified processes:")
			// Deduplicate
			seen := make(map[string]bool)
			for _, proc := range otherProcesses {
				if !seen[proc] {
					logger.Info(fmt.Sprintf("        - %s", proc))
					seen[proc] = true
				}
			}
		}
	}

	// Check for missing critical daemons
	if processCounts["ceph-mon"] == 0 {
		logger.Error("  ❌ CRITICAL: No ceph-mon processes found!")
		logger.Info("    → Monitor daemon is required for cluster operation")
		logger.Info("    → Try: systemctl start ceph-mon.target")

		// Show recent journal logs to understand why mon isn't running
		logger.Info("")
		logger.Info("Checking recent mon journal logs for errors...")

		// Use context with timeout to prevent hanging
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		journalCmd := exec.CommandContext(ctx, "journalctl", "-u", "ceph-mon@*", "-n", "50", "--no-pager")
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
				logger.Info("Recent mon journal entries (last 50 lines):")
				lines := strings.Split(outputStr, "\n")
				// Show all lines in verbose mode, or just errors in normal mode
				errorCount := 0
				for _, line := range lines {
					if verbose {
						logger.Info("  " + line)
					} else if strings.Contains(strings.ToLower(line), "error") ||
						strings.Contains(strings.ToLower(line), "fail") ||
						strings.Contains(strings.ToLower(line), "fatal") {
						logger.Error("  " + line)
						errorCount++
					}
				}
				if !verbose && errorCount == 0 {
					logger.Info("  → No obvious errors found in recent logs")
					logger.Info("  → Use --verbose to see all journal entries")
				}
			} else {
				logger.Info("  → No journal entries found for ceph-mon")
				logger.Info("  → This suggests the mon service has never been started")
			}
		}

		return DiagnosticResult{
			CheckName: "Processes",
			Passed:    false,
			Error:     fmt.Errorf("no ceph-mon processes - cluster cannot operate"),
		}
	}

	if processCounts["ceph-mgr"] == 0 {
		logger.Warn("  ⚠️  WARNING: No ceph-mgr processes found")
		logger.Info("    → Manager daemon is required for modern Ceph")
		logger.Info("    → Try: systemctl start ceph-mgr.target")
	}

	// Show full process list in verbose mode
	if verbose {
		logger.Info("")
		logger.Info("Full process list:")
		for _, proc := range cephProcesses {
			logger.Info("  " + proc)
		}
	}

	return DiagnosticResult{
		CheckName: "Processes",
		Passed:    true,
	}
}
