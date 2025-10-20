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
		"ceph-mon":   0,
		"ceph-mgr":   0,
		"ceph-osd":   0,
		"ceph-mds":   0,
		"ceph-crash": 0,
		"other":      0,
	}

	cephProcesses := []string{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "ceph") && !strings.Contains(line, "grep") && !strings.Contains(line, "ps aux") {
			cephProcesses = append(cephProcesses, strings.TrimSpace(line))

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
			default:
				processCounts["other"]++
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
	for daemonType, count := range processCounts {
		if count > 0 {
			status := "✓"
			if daemonType == "ceph-mon" || daemonType == "ceph-mgr" {
				// Critical daemons
				logger.Info(fmt.Sprintf("  %s %s: %d process(es) running", status, daemonType, count))
			} else {
				logger.Info(fmt.Sprintf("    %s: %d process(es)", daemonType, count))
			}
		}
	}

	// Check for missing critical daemons
	if processCounts["ceph-mon"] == 0 {
		logger.Error("  ❌ CRITICAL: No ceph-mon processes found!")
		logger.Info("    → Monitor daemon is required for cluster operation")
		logger.Info("    → Try: systemctl start ceph-mon.target")
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
