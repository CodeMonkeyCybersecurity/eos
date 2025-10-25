// pkg/ceph/logs.go
package ceph

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AnalyzeLogsDeep performs deep log analysis
func AnalyzeLogsDeep(logger otelzap.LoggerWithCtx, lines int, verbose bool) DiagnosticResult {
	errorsFound := false

	// Check for ANY Ceph-related systemd logs
	logger.Info("Checking systemd journal for Ceph services...")
	cmd := exec.Command("journalctl", "-u", "ceph*", "--since", "1 hour ago", "-n", fmt.Sprintf("%d", lines), "--no-pager")
	if output, err := cmd.Output(); err == nil {
		logStr := string(output)
		if len(strings.TrimSpace(logStr)) == 0 {
			logger.Warn("  No systemd journal entries found for Ceph services")
			logger.Info("  → This suggests Ceph services have never started or are not configured")
			errorsFound = true
		} else {
			if verbose {
				logger.Info("Recent Ceph systemd logs:")
				for _, line := range strings.Split(logStr, "\n") {
					if strings.TrimSpace(line) != "" {
						logger.Info("  " + line)
					}
				}
			}
			if strings.Contains(logStr, "ERROR") || strings.Contains(logStr, "CRITICAL") || strings.Contains(logStr, "failed") {
				logger.Warn("  Errors found in systemd logs")
				errorsFound = true
			}
		}
	} else {
		logger.Warn("Could not read systemd journal", zap.Error(err))
	}

	// Check /var/log/ceph/ directory
	logger.Info("Checking /var/log/ceph/ directory...")
	cmd = exec.Command("ls", "-lah", "/var/log/ceph/")
	if output, err := cmd.Output(); err == nil {
		logStr := string(output)
		if verbose {
			logger.Info("Ceph log directory contents:")
			for _, line := range strings.Split(logStr, "\n") {
				if strings.TrimSpace(line) != "" {
					logger.Info("  " + line)
				}
			}
		}

		// Check for recent log files
		cmd = exec.Command("find", "/var/log/ceph/", "-type", "f", "-mtime", "-1")
		if output, err := cmd.Output(); err == nil {
			files := strings.TrimSpace(string(output))
			if files == "" {
				logger.Warn("  No recent log files (modified in last 24h)")
				logger.Info("  → Ceph daemons may not be running")
				errorsFound = true
			} else {
				logger.Info("Recent log files found:")
				for _, file := range strings.Split(files, "\n") {
					if strings.TrimSpace(file) != "" {
						logger.Info("  " + file)

						// Check last few lines of each log file for errors
						if verbose {
							tailCmd := exec.Command("tail", "-n", "10", file)
							if tailOutput, err := tailCmd.Output(); err == nil {
								logger.Info(fmt.Sprintf("  Last 10 lines of %s:", file))
								for _, line := range strings.Split(string(tailOutput), "\n") {
									if strings.TrimSpace(line) != "" {
										logger.Info("    " + line)
									}
								}
							}
						}
					}
				}
			}
		}
	} else {
		logger.Warn("  Cannot access /var/log/ceph/", zap.Error(err))
		logger.Info("  → Directory may not exist or insufficient permissions")
		errorsFound = true
	}

	// Check for crash dumps
	logger.Info("Checking for crash dumps...")
	cmd = exec.Command("ls", "-lah", "/var/lib/ceph/crash/")
	if output, err := cmd.Output(); err == nil {
		logStr := string(output)
		if strings.Contains(logStr, "total 0") || len(strings.Split(logStr, "\n")) <= 3 {
			logger.Info("✓ No crash dumps found")
		} else {
			logger.Warn("  Crash dumps detected:")
			for _, line := range strings.Split(logStr, "\n") {
				if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "total") {
					logger.Warn("  " + line)
				}
			}
			errorsFound = true
		}
	}

	if errorsFound {
		return DiagnosticResult{
			CheckName: "Log Analysis",
			Passed:    false,
			Error:     fmt.Errorf("log analysis found issues"),
		}
	}

	logger.Info(fmt.Sprintf("✓ Analyzed logs (last %d lines)", lines))
	return DiagnosticResult{
		CheckName: "Log Analysis",
		Passed:    true,
	}
}
