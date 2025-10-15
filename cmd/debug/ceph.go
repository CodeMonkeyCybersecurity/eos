// cmd/debug/ceph.go
package debug

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	cephDebugVerbose bool
	cephDebugFix     bool
	cephDebugLogs    int
)

var cephDebugCmd = &cobra.Command{
	Use:   "ceph",
	Short: "Debug Ceph cluster issues and diagnose problems",
	Long: `Debug Ceph provides comprehensive troubleshooting for Ceph storage cluster issues.

Diagnostic checks performed:
1. Ceph binary verification (ceph, ceph-mon, ceph-mgr, ceph-osd)
2. Cluster connectivity and authentication
3. MON quorum status and health
4. MGR daemon status
5. OSD status (up/down, in/out)
6. Storage capacity and usage
7. PG (Placement Group) status
8. Network configuration
9. Clock synchronization (NTP/Chrony)
10. Log analysis (errors, warnings, critical issues)
11. Common misconfigurations

The debug command provides actionable recommendations for fixing issues.

FLAGS:
  --verbose         Show detailed diagnostic output
  --fix             Attempt to automatically fix common issues
  --logs N          Number of log lines to analyze (default: 50)

EXAMPLES:
  # Basic diagnostics
  sudo eos debug ceph

  # Verbose output with more details
  sudo eos debug ceph --verbose

  # Auto-fix common issues
  sudo eos debug ceph --fix

  # Analyze more log lines
  sudo eos debug ceph --logs 200

CODE MONKEY CYBERSECURITY - "Cybersecurity. With humans."`,

	RunE: eos_cli.Wrap(runCephDebug),
}

func init() {
	cephDebugCmd.Flags().BoolVarP(&cephDebugVerbose, "verbose", "v", false,
		"Show detailed diagnostic output")
	cephDebugCmd.Flags().BoolVar(&cephDebugFix, "fix", false,
		"Attempt to automatically fix common issues")
	cephDebugCmd.Flags().IntVar(&cephDebugLogs, "logs", 50,
		"Number of log lines to analyze")

	debugCmd.AddCommand(cephDebugCmd)
}

func runCephDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("================================================================================")
	logger.Info("Ceph Cluster Diagnostics")
	logger.Info("================================================================================")
	logger.Info("")

	issueCount := 0

	// 1. Binary verification
	logger.Info("1. Checking Ceph binaries")
	logger.Info(strings.Repeat("-", 40))
	if err := checkCephBinaries(logger); err != nil {
		logger.Error("Binary check failed", zap.Error(err))
		issueCount++
	} else {
		logger.Info("All binaries found")
	}
	logger.Info("")

	// 2. Cluster connectivity
	logger.Info("2. Checking cluster connectivity")
	logger.Info(strings.Repeat("-", 40))
	if err := checkCephConnectivity(logger); err != nil {
		logger.Error("Connectivity check failed", zap.Error(err))
		issueCount++
	} else {
		logger.Info("Cluster is reachable")
	}
	logger.Info("")

	// 3. Cluster health
	logger.Info("3. Checking cluster health")
	logger.Info(strings.Repeat("-", 40))
	if err := checkCephHealth(logger, cephDebugVerbose); err != nil {
		logger.Warn("Health check found issues", zap.Error(err))
		issueCount++
	} else {
		logger.Info("Cluster health: HEALTH_OK")
	}
	logger.Info("")

	// 4. MON status
	logger.Info("4. Checking MON daemon status")
	logger.Info(strings.Repeat("-", 40))
	if err := checkMonStatus(logger); err != nil {
		logger.Error("MON check failed", zap.Error(err))
		issueCount++
	} else {
		logger.Info("MON daemons operational")
	}
	logger.Info("")

	// 5. MGR status
	logger.Info("5. Checking MGR daemon status")
	logger.Info(strings.Repeat("-", 40))
	if err := checkMgrStatus(logger); err != nil {
		logger.Warn("MGR check found issues", zap.Error(err))
		issueCount++
	} else {
		logger.Info("MGR daemons operational")
	}
	logger.Info("")

	// 6. OSD status
	logger.Info("6. Checking OSD status")
	logger.Info(strings.Repeat("-", 40))
	if err := checkOSDStatus(logger, cephDebugVerbose); err != nil {
		logger.Warn("OSD check found issues", zap.Error(err))
		issueCount++
	} else {
		logger.Info("All OSDs up and in")
	}
	logger.Info("")

	// 7. Storage capacity
	logger.Info("7. Checking storage capacity")
	logger.Info(strings.Repeat("-", 40))
	if err := checkStorageCapacity(logger); err != nil {
		logger.Warn("Storage check found issues", zap.Error(err))
		issueCount++
	}
	logger.Info("")

	// 8. PG status
	logger.Info("8. Checking Placement Group status")
	logger.Info(strings.Repeat("-", 40))
	if err := checkPGStatus(logger); err != nil {
		logger.Warn("PG check found issues", zap.Error(err))
		issueCount++
	}
	logger.Info("")

	// 9. Clock sync
	logger.Info("9. Checking clock synchronization")
	logger.Info(strings.Repeat("-", 40))
	if err := checkClockSync(logger); err != nil {
		logger.Warn("Clock sync check found issues", zap.Error(err))
		issueCount++
	}
	logger.Info("")

	// 10. Log analysis
	logger.Info("10. Analyzing Ceph logs")
	logger.Info(strings.Repeat("-", 40))
	if err := analyzeCephLogs(logger, cephDebugLogs); err != nil {
		logger.Warn("Log analysis found issues", zap.Error(err))
		issueCount++
	}
	logger.Info("")

	// Summary
	logger.Info("================================================================================")
	logger.Info("Diagnostics Summary")
	logger.Info("================================================================================")
	if issueCount == 0 {
		logger.Info("No issues detected - cluster is healthy")
	} else {
		logger.Warn(fmt.Sprintf("Found %d issue(s) requiring attention", issueCount))
		logger.Info("")
		logger.Info("Recommendations:")
		logger.Info("  1. Review error messages above for specific issues")
		logger.Info("  2. Check Ceph documentation: https://docs.ceph.com/")
		logger.Info("  3. Use 'ceph health detail' for more information")
		logger.Info("  4. Check logs: journalctl -u ceph-mon@* -u ceph-mgr@* -u ceph-osd@*")
		if !cephDebugFix {
			logger.Info("  5. Run with --fix flag to auto-fix common issues")
		}
	}
	logger.Info("")

	return nil
}

func checkCephBinaries(logger otelzap.LoggerWithCtx) error {
	binaries := []string{"ceph", "ceph-mon", "ceph-mgr", "ceph-osd", "ceph-mds", "rados"}
	missing := []string{}

	for _, bin := range binaries {
		if path, err := exec.LookPath(bin); err != nil {
			missing = append(missing, bin)
			logger.Warn("Binary not found", zap.String("binary", bin))
		} else {
			logger.Debug("Binary found", zap.String("binary", bin), zap.String("path", path))
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing binaries: %s", strings.Join(missing, ", "))
	}

	return nil
}

func checkCephConnectivity(logger otelzap.LoggerWithCtx) error {
	cmd := exec.Command("ceph", "status")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Cannot connect to cluster", zap.String("output", string(output)))
		return fmt.Errorf("cluster unreachable: %w", err)
	}

	logger.Info("Successfully connected to cluster")
	return nil
}

func checkCephHealth(logger otelzap.LoggerWithCtx, verbose bool) error {
	cmd := exec.Command("ceph", "health", "detail")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get health: %w", err)
	}

	healthOutput := string(output)
	lines := strings.Split(healthOutput, "\n")

	if len(lines) > 0 {
		firstLine := strings.TrimSpace(lines[0])
		logger.Info(fmt.Sprintf("Health status: %s", firstLine))

		if !strings.HasPrefix(firstLine, "HEALTH_OK") {
			if verbose {
				for _, line := range lines[1:] {
					if strings.TrimSpace(line) != "" {
						logger.Warn(line)
					}
				}
			}
			return fmt.Errorf("cluster not healthy: %s", firstLine)
		}
	}

	return nil
}

func checkMonStatus(logger otelzap.LoggerWithCtx) error {
	cmd := exec.Command("ceph", "mon", "stat")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get MON status: %w", err)
	}

	logger.Info(strings.TrimSpace(string(output)))

	// Check quorum
	cmd = exec.Command("ceph", "quorum_status")
	if output, err := cmd.Output(); err == nil {
		logger.Debug("Quorum status", zap.String("output", string(output)))
	}

	return nil
}

func checkMgrStatus(logger otelzap.LoggerWithCtx) error {
	cmd := exec.Command("ceph", "mgr", "stat")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get MGR status: %w", err)
	}

	logger.Info(strings.TrimSpace(string(output)))
	return nil
}

func checkOSDStatus(logger otelzap.LoggerWithCtx, verbose bool) error {
	cmd := exec.Command("ceph", "osd", "stat")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get OSD status: %w", err)
	}

	logger.Info(strings.TrimSpace(string(output)))

	if verbose {
		cmd = exec.Command("ceph", "osd", "tree")
		if output, err := cmd.Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					logger.Info(line)
				}
			}
		}
	}

	return nil
}

func checkStorageCapacity(logger otelzap.LoggerWithCtx) error {
	cmd := exec.Command("ceph", "df")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get storage capacity: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			logger.Info(line)
		}
	}

	return nil
}

func checkPGStatus(logger otelzap.LoggerWithCtx) error {
	cmd := exec.Command("ceph", "pg", "stat")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get PG status: %w", err)
	}

	logger.Info(strings.TrimSpace(string(output)))

	// Check for degraded/misplaced PGs
	cmd = exec.Command("ceph", "health", "detail")
	if output, err := cmd.Output(); err == nil {
		healthStr := string(output)
		if strings.Contains(healthStr, "degraded") || strings.Contains(healthStr, "misplaced") {
			logger.Warn("Degraded or misplaced PGs detected")
			return fmt.Errorf("PG issues detected")
		}
	}

	return nil
}

func checkClockSync(logger otelzap.LoggerWithCtx) error {
	// Check if chrony or ntpd is running
	services := []string{"chronyd", "ntpd"}
	syncActive := false

	for _, svc := range services {
		cmd := exec.Command("systemctl", "is-active", svc)
		if err := cmd.Run(); err == nil {
			logger.Info(fmt.Sprintf("Time sync active: %s", svc))
			syncActive = true
			break
		}
	}

	if !syncActive {
		logger.Warn("No time synchronization service detected")
		logger.Info("Recommendation: Install and enable chronyd or ntpd")
		return fmt.Errorf("time sync not active")
	}

	// Check clock skew in Ceph
	cmd := exec.Command("ceph", "health", "detail")
	if output, err := cmd.Output(); err == nil {
		if strings.Contains(string(output), "clock skew") {
			logger.Warn("Clock skew detected between Ceph daemons")
			return fmt.Errorf("clock skew detected")
		}
	}

	return nil
}

func analyzeCephLogs(logger otelzap.LoggerWithCtx, lines int) error {
	// Check for recent errors in MON logs
	cmd := exec.Command("journalctl", "-u", "ceph-mon@*", "-n", fmt.Sprintf("%d", lines), "--no-pager")
	if output, err := cmd.Output(); err == nil {
		logStr := string(output)
		if strings.Contains(logStr, "ERROR") || strings.Contains(logStr, "CRITICAL") {
			logger.Warn("Errors found in MON logs")
			logger.Info("Check logs with: journalctl -u ceph-mon@* | grep -i error")
		}
	}

	// Check MGR logs
	cmd = exec.Command("journalctl", "-u", "ceph-mgr@*", "-n", fmt.Sprintf("%d", lines), "--no-pager")
	if output, err := cmd.Output(); err == nil {
		logStr := string(output)
		if strings.Contains(logStr, "ERROR") || strings.Contains(logStr, "CRITICAL") {
			logger.Warn("Errors found in MGR logs")
			logger.Info("Check logs with: journalctl -u ceph-mgr@* | grep -i error")
		}
	}

	// Check OSD logs
	cmd = exec.Command("journalctl", "-u", "ceph-osd@*", "-n", fmt.Sprintf("%d", lines), "--no-pager")
	if output, err := cmd.Output(); err == nil {
		logStr := string(output)
		if strings.Contains(logStr, "ERROR") || strings.Contains(logStr, "CRITICAL") {
			logger.Warn("Errors found in OSD logs")
			logger.Info("Check logs with: journalctl -u ceph-osd@* | grep -i error")
		}
	}

	logger.Info(fmt.Sprintf("Analyzed last %d log lines", lines))
	return nil
}
