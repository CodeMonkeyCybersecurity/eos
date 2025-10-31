// pkg/ceph/monitor.go
package ceph

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckMonitorBootstrap performs deep dive into monitor initialization state
// This is a CRITICAL check that identifies if the monitor was never bootstrapped
func CheckMonitorBootstrap(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	logger.Info("Checking monitor initialization (bootstrap) state...")

	result := DiagnosticResult{
		CheckName: "Monitor Bootstrap",
		Passed:    true,
		Issues:    []Issue{},
	}

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		logger.Warn("  Could not determine hostname", zap.Error(err))
		hostname = "unknown"
	}

	logger.Info(fmt.Sprintf("  This host: %s", hostname))

	// Check if monitor data directory exists
	monDataDir := filepath.Join("/var/lib/ceph/mon", fmt.Sprintf("ceph-%s", hostname))

	if _, err := os.Stat(monDataDir); os.IsNotExist(err) {
		// ROOT CAUSE IDENTIFIED: Monitor was never bootstrapped!
		logger.Error("❌ CRITICAL: Monitor data directory does not exist!")
		logger.Info(fmt.Sprintf("  → Path checked: %s", monDataDir))
		logger.Info("  → This means the monitor was never bootstrapped on this host")
		logger.Info("")
		logger.Info("╔════════════════════════════════════════════════════════════════╗")
		logger.Info("║  AUTOMATED BOOTSTRAP AVAILABLE                                 ║")
		logger.Info("╚════════════════════════════════════════════════════════════════╝")
		logger.Info("")
		logger.Info("Use Eos automated bootstrap (RECOMMENDED):")
		logger.Info("  sudo eos update ceph --fix --bootstrap-mon")
		logger.Info("")
		logger.Info("This will perform the complete 9-step Ceph bootstrap process:")
		logger.Info("  1. Pre-flight validation (prevent split-brain)")
		logger.Info("  2. Generate cluster FSID (UUID)")
		logger.Info("  3. Create /etc/ceph/ceph.conf with required settings")
		logger.Info("  4. Create monitor, admin, and bootstrap keyrings")
		logger.Info("  5. Generate monmap")
		logger.Info("  6. Initialize monitor database")
		logger.Info("  7. Fix ownership and permissions")
		logger.Info("  8. Start monitor service")
		logger.Info("  9. Verify monitor health")
		logger.Info("")
		logger.Info("For manual bootstrap, see:")
		logger.Info("  https://docs.ceph.com/en/latest/install/manual-deployment/")
		logger.Info("")
		logger.Warn("WARNING: Manual bootstrap is complex and error-prone.")
		logger.Warn("         The automated method is strongly recommended.")

		result.Passed = false
		result.Error = fmt.Errorf("monitor was never bootstrapped on this host")
		result.Issues = append(result.Issues, Issue{
			Component:   "ceph-mon",
			Severity:    "critical",
			Description: "Monitor was never bootstrapped on this host",
			Impact:      "Monitor cannot start because it was never initialized. This is the root cause preventing the cluster from operating.",
			Remediation: []string{
				"Use automated bootstrap (RECOMMENDED):",
				"  sudo eos update ceph --fix --bootstrap-mon",
				"",
				"This performs complete Ceph bootstrap with all required steps.",
				"Manual bootstrap is complex - see https://docs.ceph.com/en/latest/install/manual-deployment/",
			},
		})

		return result
	}

	// Monitor directory exists - check its contents
	logger.Info(fmt.Sprintf("✓ Monitor data directory exists: %s", monDataDir))

	// Check directory contents
	entries, err := os.ReadDir(monDataDir)
	if err != nil {
		logger.Warn("  Cannot read monitor directory", zap.Error(err))
		result.Issues = append(result.Issues, Issue{
			Component:   "ceph-mon",
			Severity:    "warning",
			Description: "Monitor directory exists but cannot be read",
			Impact:      "Cannot verify monitor data integrity",
			Remediation: []string{
				fmt.Sprintf("Check permissions: ls -la %s", monDataDir),
				fmt.Sprintf("Check ownership: stat %s", monDataDir),
			},
		})
	} else {
		logger.Info(fmt.Sprintf("  Monitor data directory contains %d files/dirs", len(entries)))

		// Check for critical files
		keyFiles := []string{"keyring", "store.db", "kv_backend"}
		missingFiles := []string{}

		for _, keyFile := range keyFiles {
			keyPath := filepath.Join(monDataDir, keyFile)
			if _, err := os.Stat(keyPath); err == nil {
				logger.Info(fmt.Sprintf("    ✓ %s exists", keyFile))
			} else {
				logger.Warn(fmt.Sprintf("      %s missing", keyFile))
				missingFiles = append(missingFiles, keyFile)
			}
		}

		if len(missingFiles) > 0 {
			result.Passed = false
			result.Issues = append(result.Issues, Issue{
				Component:   "ceph-mon",
				Severity:    "warning",
				Description: fmt.Sprintf("Monitor directory missing critical files: %s", strings.Join(missingFiles, ", ")),
				Impact:      "Monitor may have incomplete data or corrupted state",
				Remediation: []string{
					fmt.Sprintf("Check journal for errors: journalctl -u ceph-mon@%s -n 100", hostname),
					"Monitor may need to be re-initialized",
					"Consider restoring from backup if available",
				},
			})
		}
	}

	// Check recent journal entries for monitor
	logger.Info("")
	logger.Info("Checking recent monitor journal logs...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "journalctl", "-u", fmt.Sprintf("ceph-mon@%s", hostname), "-n", "20", "--no-pager")
	output, err := cmd.Output()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			logger.Warn("  → Journal query timed out after 10 seconds")
		} else {
			logger.Warn("  → Could not access journal logs", zap.Error(err))
		}
	} else {
		lines := strings.Split(string(output), "\n")
		errorCount := 0
		errorLines := []string{}

		for _, line := range lines {
			lineLower := strings.ToLower(line)
			if strings.Contains(lineLower, "error") || strings.Contains(lineLower, "failed") {
				if errorCount < 5 {
					errorLines = append(errorLines, line)
				}
				errorCount++
			}
		}

		if errorCount == 0 {
			logger.Info("  ✓ No recent error messages in journal")
		} else {
			logger.Warn(fmt.Sprintf("    Found %d error message(s) - showing first 5:", errorCount))
			for _, line := range errorLines {
				logger.Warn("    " + line)
			}
			logger.Info(fmt.Sprintf("  → Full logs: journalctl -u ceph-mon@%s -n 100", hostname))

			if errorCount > 0 {
				result.Issues = append(result.Issues, Issue{
					Component:   "ceph-mon",
					Severity:    "warning",
					Description: fmt.Sprintf("Found %d error messages in recent monitor logs", errorCount),
					Impact:      "Monitor may be experiencing runtime issues",
					Remediation: []string{
						fmt.Sprintf("Review full logs: journalctl -u ceph-mon@%s -n 100", hostname),
						fmt.Sprintf("Check monitor status: systemctl status ceph-mon@%s", hostname),
						"Check cluster health: ceph health detail (if cluster is reachable)",
					},
				})
			}
		}

		// Show all logs in verbose mode
		if verbose && len(lines) > 0 {
			logger.Info("")
			logger.Info("Recent monitor journal entries (last 20):")
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					logger.Info("  " + line)
				}
			}
		}
	}

	// Check if monitor service exists and its state
	logger.Info("")
	logger.Info("Checking monitor service state...")

	serviceName := fmt.Sprintf("ceph-mon@%s.service", hostname)
	cmd = exec.Command("systemctl", "is-active", serviceName)
	output, _ = cmd.Output()
	status := strings.TrimSpace(string(output))

	cmd = exec.Command("systemctl", "is-enabled", serviceName)
	enabledOutput, _ := cmd.Output()
	enabled := strings.TrimSpace(string(enabledOutput))

	logger.Info(fmt.Sprintf("  Service: %s", serviceName))
	logger.Info(fmt.Sprintf("    Status: %s", status))
	logger.Info(fmt.Sprintf("    Enabled: %s", enabled))

	if status != "active" {
		logger.Error(fmt.Sprintf("  ❌ Monitor service is %s (not running)", status))
		logger.Info("  → Try: systemctl start " + serviceName)

		result.Passed = false
		result.Issues = append(result.Issues, Issue{
			Component:   "ceph-mon",
			Severity:    "critical",
			Description: fmt.Sprintf("Monitor service is %s", status),
			Impact:      "Monitor daemon is not running - cluster cannot operate",
			Remediation: []string{
				fmt.Sprintf("Check why service failed: systemctl status %s", serviceName),
				fmt.Sprintf("View detailed logs: journalctl -u %s -xe", serviceName),
				fmt.Sprintf("Try starting: systemctl start %s", serviceName),
			},
		})
	} else {
		logger.Info("  ✓ Monitor service is active and running")
	}

	if enabled != "enabled" {
		logger.Warn("    Monitor service is not enabled (won't start on boot)")
		logger.Info("  → Try: systemctl enable " + serviceName)

		result.Issues = append(result.Issues, Issue{
			Component:   "ceph-mon",
			Severity:    "warning",
			Description: "Monitor service is not enabled",
			Impact:      "Monitor will not start automatically after reboot",
			Remediation: []string{
				fmt.Sprintf("systemctl enable %s", serviceName),
			},
		})
	}

	return result
}
