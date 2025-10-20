// pkg/ceph/processes.go
package ceph

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// CheckProcesses checks if any Ceph processes are running
func CheckProcesses(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	logger.Info("Checking for Ceph processes...")

	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
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
	for _, line := range lines {
		if strings.Contains(line, "ceph") && !strings.Contains(line, "grep") && !strings.Contains(line, "ps aux") {
			cephProcesses = append(cephProcesses, strings.TrimSpace(line))

			// Extract process name from ps output
			fields := strings.Fields(line)
			var processName string
			if len(fields) >= 11 {
				// ps aux format: USER PID ... COMMAND
				processName = fields[10]
			}

			// Count by type
			switch {
			case strings.Contains(line, "ceph-mon"):
				processCounts["ceph-mon"]++
			case strings.Contains(line, "ceph-mgr"):
				processCounts["ceph-mgr"]++
			case strings.Contains(line, "ceph-osd"):
				processCounts["ceph-osd"]++
			case strings.Contains(line, "ceph-mds"):
				processCounts["ceph-mds"]++
			case strings.Contains(line, "ceph-crash"):
				processCounts["ceph-crash"]++
			case strings.Contains(line, "ceph-volume"):
				processCounts["ceph-volume"]++
			case strings.Contains(line, "radosgw"):
				processCounts["radosgw"]++
			case strings.Contains(line, "rbd-mirror"):
				processCounts["rbd-mirror"]++
			default:
				processCounts["other"]++
				// Track what these "other" processes are
				if processName != "" && !strings.Contains(processName, "ps") {
					otherProcesses = append(otherProcesses, processName)
				}
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
		cmd := exec.Command("journalctl", "-u", "ceph-mon@*", "-n", "50", "--no-pager")
		output, err := cmd.Output()
		if err == nil {
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
		} else {
			logger.Warn("  → Could not access journal logs")
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
