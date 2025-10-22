// pkg/ceph/diagnostics.go
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

// Issue represents a specific problem found during diagnostics
type Issue struct {
	Component   string   // e.g., "ceph-mon", "configuration"
	Severity    string   // "critical", "warning", "info"
	Description string   // Human-readable description
	Impact      string   // Why this matters
	Remediation []string // Specific commands to fix
}

// DiagnosticResult represents the result of a diagnostic check
type DiagnosticResult struct {
	CheckName string
	Passed    bool
	Error     error
	Details   string
	Issues    []Issue // Detailed issues found in this check
}

// DiagnosticOptions contains options for running diagnostics
type DiagnosticOptions struct {
	Verbose  bool
	Fix      bool
	LogLines int
}

// RunFullDiagnostics runs all Ceph diagnostic checks
func RunFullDiagnostics(logger otelzap.LoggerWithCtx, opts DiagnosticOptions) ([]DiagnosticResult, bool) {
	results := []DiagnosticResult{}
	clusterReachable := false

	// 0. Installation State
	result := CheckInstallation(logger, opts.Verbose)
	results = append(results, result)

	// 1. Binaries
	result = CheckBinaries(logger)
	results = append(results, result)

	// 1a. Processes
	result = CheckProcesses(logger, opts.Verbose)
	results = append(results, result)

	// 1b. Systemd Units
	result = CheckSystemdUnits(logger, opts.Verbose)
	results = append(results, result)

	// 1c. Monitor Bootstrap Check (NEW - Critical diagnostic)
	result = CheckMonitorBootstrap(logger, opts.Verbose)
	results = append(results, result)

	// 1d. Configuration
	result = CheckConfiguration(logger, opts.Verbose)
	results = append(results, result)

	// 1e. Network
	result = CheckNetwork(logger, opts.Verbose)
	results = append(results, result)

	// 1f. Storage
	result = CheckStorage(logger, opts.Verbose)
	results = append(results, result)

	// 2. Connectivity
	result = CheckConnectivity(logger)
	results = append(results, result)
	clusterReachable = result.Passed

	// Cluster-level checks (only if reachable)
	if clusterReachable {
		result = CheckHealth(logger, opts.Verbose)
		results = append(results, result)

		result = CheckMonStatus(logger)
		results = append(results, result)

		result = CheckMgrStatus(logger)
		results = append(results, result)

		result = CheckOSDStatus(logger, opts.Verbose)
		results = append(results, result)

		result = CheckStorageCapacity(logger)
		results = append(results, result)

		result = CheckPGStatus(logger)
		results = append(results, result)

		result = CheckClockSync(logger)
		results = append(results, result)
	} else {
		logger.Warn("⚠️  Skipping cluster-level checks (cluster not reachable)")
		logger.Info("")
	}

	// 10. Logs (always run)
	result = AnalyzeLogsDeep(logger, opts.LogLines, opts.Verbose)
	results = append(results, result)

	return results, clusterReachable
}

// CheckBinaries verifies all required Ceph binaries are present
func CheckBinaries(logger otelzap.LoggerWithCtx) DiagnosticResult {
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
		return DiagnosticResult{
			CheckName: "Binaries",
			Passed:    false,
			Error:     fmt.Errorf("missing binaries: %s", strings.Join(missing, ", ")),
		}
	}

	return DiagnosticResult{
		CheckName: "Binaries",
		Passed:    true,
	}
}

// CheckConnectivity tests connection to the Ceph cluster
func CheckConnectivity(logger otelzap.LoggerWithCtx) DiagnosticResult {
	logger.Info("Attempting to connect to Ceph cluster...")
	logger.Info("  Command: ceph status --connect-timeout=5")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ceph", "status", "--connect-timeout=5")
	output, err := cmd.CombinedOutput()

	if err != nil {
		outputStr := strings.TrimSpace(string(output))

		if ctx.Err() == context.DeadlineExceeded {
			logger.Error("❌ Cluster connection timed out after 10 seconds")
			if outputStr != "" {
				logger.Error("  Command output:")
				for _, line := range strings.Split(outputStr, "\n") {
					logger.Error("    " + line)
				}
			}
			logger.Info("")
			logger.Info("Possible causes:")
			logger.Info("  1. Monitor daemon (ceph-mon) is not running")
			logger.Info("  2. Monitor ports (3300, 6789) are not accessible")
			logger.Info("  3. Network connectivity to monitor host failed")
			logger.Info("  4. Configuration file (/etc/ceph/ceph.conf) is incorrect")
			logger.Info("  5. Authentication keyring is missing or has wrong permissions")
			logger.Info("")
			logger.Info("Diagnostic commands:")
			logger.Info("  • Check mon process: ps aux | grep ceph-mon")
			logger.Info("  • Check mon logs: journalctl -u ceph-mon@* -n 50")
			logger.Info("  • Check ports: ss -tlnp | grep -E '(3300|6789)'")
			logger.Info("  • Test manually: ceph -s --debug-ms 1")

			return DiagnosticResult{
				CheckName: "Connectivity",
				Passed:    false,
				Error:     fmt.Errorf("cluster connection timeout - cluster may be down or unreachable"),
			}
		}

		// Non-timeout error
		logger.Error("❌ Cannot connect to cluster")
		logger.Error(fmt.Sprintf("  Exit code: %v", err))

		if outputStr != "" {
			logger.Error("  Error output:")
			for _, line := range strings.Split(outputStr, "\n") {
				logger.Error("    " + line)
			}
		}

		// Try to provide specific guidance based on error message
		outputLower := strings.ToLower(outputStr)
		logger.Info("")
		logger.Info("Likely cause and remediation:")
		switch {
		case strings.Contains(outputLower, "no such file"):
			logger.Info("  → Configuration file or keyring not found")
			logger.Info("  → Check: ls -la /etc/ceph/")
			logger.Info("  → Expected files: ceph.conf, ceph.client.admin.keyring")
		case strings.Contains(outputLower, "permission denied"):
			logger.Info("  → Insufficient permissions to read keyring")
			logger.Info("  → Check: ls -la /etc/ceph/*.keyring")
			logger.Info("  → Fix: sudo chmod 644 /etc/ceph/*.keyring")
		case strings.Contains(outputLower, "authentication"):
			logger.Info("  → Keyring authentication failed")
			logger.Info("  → Verify keyring matches cluster")
			logger.Info("  → Try: ceph auth list (from working node)")
		case strings.Contains(outputLower, "connection refused"):
			logger.Info("  → Monitor is not listening on expected ports")
			logger.Info("  → Check: ss -tlnp | grep -E '(3300|6789)'")
			logger.Info("  → Check: ps aux | grep ceph-mon")
			logger.Info("  → Start: systemctl start ceph-mon.target")
		case strings.Contains(outputLower, "connection timed out") || strings.Contains(outputLower, "timed out"):
			// Combine both timeout cases since "connection timed out" contains "timed out"
			logger.Info("  → Connection to monitor timed out")
			logger.Info("  → Possible causes:")
			logger.Info("    1. Monitor process is not running (check: ps aux | grep ceph-mon)")
			logger.Info("    2. Monitor ports not listening (check: ss -tlnp | grep -E '(3300|6789)')")
			logger.Info("    3. Firewall blocking connection (check: sudo ufw status)")
			logger.Info("    4. Wrong monitor address in config (check: grep mon_host /etc/ceph/ceph.conf)")
			logger.Info("    5. Network routing issue (check: ip route get <monitor-ip>)")
		default:
			logger.Info("  → Unknown connection error (see output above)")
			logger.Info("  → Try: ceph -s --debug-ms 1 for detailed output")
			logger.Info("  → Check: journalctl -u ceph-mon@* -n 50")
		}

		return DiagnosticResult{
			CheckName: "Connectivity",
			Passed:    false,
			Error:     fmt.Errorf("cluster unreachable: %w", err),
		}
	}

	// Success!
	logger.Info("✓ Successfully connected to cluster")
	logger.Info("")
	logger.Info("Cluster status preview:")
	// Show first few lines of status
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i >= 10 {
			break
		}
		if strings.TrimSpace(line) != "" {
			logger.Info("  " + line)
		}
	}

	return DiagnosticResult{
		CheckName: "Connectivity",
		Passed:    true,
	}
}

// CheckHealth checks Ceph cluster health
func CheckHealth(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	cmd := exec.Command("ceph", "health", "detail")
	output, err := cmd.Output()
	if err != nil {
		return DiagnosticResult{
			CheckName: "Health",
			Passed:    false,
			Error:     fmt.Errorf("failed to get health: %w", err),
		}
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
			return DiagnosticResult{
				CheckName: "Health",
				Passed:    false,
				Error:     fmt.Errorf("cluster not healthy: %s", firstLine),
			}
		}
	}

	return DiagnosticResult{
		CheckName: "Health",
		Passed:    true,
	}
}

// CheckMonStatus checks MON daemon status
func CheckMonStatus(logger otelzap.LoggerWithCtx) DiagnosticResult {
	cmd := exec.Command("ceph", "mon", "stat")
	output, err := cmd.Output()
	if err != nil {
		return DiagnosticResult{
			CheckName: "MON Status",
			Passed:    false,
			Error:     fmt.Errorf("failed to get MON status: %w", err),
		}
	}

	logger.Info(strings.TrimSpace(string(output)))

	// Check quorum
	cmd = exec.Command("ceph", "quorum_status")
	if output, err := cmd.Output(); err == nil {
		logger.Debug("Quorum status", zap.String("output", string(output)))
	}

	return DiagnosticResult{
		CheckName: "MON Status",
		Passed:    true,
	}
}

// CheckMgrStatus checks MGR daemon status
func CheckMgrStatus(logger otelzap.LoggerWithCtx) DiagnosticResult {
	cmd := exec.Command("ceph", "mgr", "stat")
	output, err := cmd.Output()
	if err != nil {
		return DiagnosticResult{
			CheckName: "MGR Status",
			Passed:    false,
			Error:     fmt.Errorf("failed to get MGR status: %w", err),
		}
	}

	logger.Info(strings.TrimSpace(string(output)))

	return DiagnosticResult{
		CheckName: "MGR Status",
		Passed:    true,
	}
}

// CheckOSDStatus checks OSD daemon status
func CheckOSDStatus(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	cmd := exec.Command("ceph", "osd", "stat")
	output, err := cmd.Output()
	if err != nil {
		return DiagnosticResult{
			CheckName: "OSD Status",
			Passed:    false,
			Error:     fmt.Errorf("failed to get OSD status: %w", err),
		}
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

	return DiagnosticResult{
		CheckName: "OSD Status",
		Passed:    true,
	}
}

// CheckStorageCapacity checks storage capacity
func CheckStorageCapacity(logger otelzap.LoggerWithCtx) DiagnosticResult {
	cmd := exec.Command("ceph", "df")
	output, err := cmd.Output()
	if err != nil {
		return DiagnosticResult{
			CheckName: "Storage Capacity",
			Passed:    false,
			Error:     fmt.Errorf("failed to get storage capacity: %w", err),
		}
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			logger.Info(line)
		}
	}

	return DiagnosticResult{
		CheckName: "Storage Capacity",
		Passed:    true,
	}
}

// CheckPGStatus checks Placement Group status
func CheckPGStatus(logger otelzap.LoggerWithCtx) DiagnosticResult {
	cmd := exec.Command("ceph", "pg", "stat")
	output, err := cmd.Output()
	if err != nil {
		return DiagnosticResult{
			CheckName: "PG Status",
			Passed:    false,
			Error:     fmt.Errorf("failed to get PG status: %w", err),
		}
	}

	logger.Info(strings.TrimSpace(string(output)))

	// Check for degraded/misplaced PGs
	cmd = exec.Command("ceph", "health", "detail")
	if output, err := cmd.Output(); err == nil {
		healthStr := string(output)
		if strings.Contains(healthStr, "degraded") || strings.Contains(healthStr, "misplaced") {
			logger.Warn("Degraded or misplaced PGs detected")
			return DiagnosticResult{
				CheckName: "PG Status",
				Passed:    false,
				Error:     fmt.Errorf("PG issues detected"),
			}
		}
	}

	return DiagnosticResult{
		CheckName: "PG Status",
		Passed:    true,
	}
}

// CheckClockSync checks clock synchronization
func CheckClockSync(logger otelzap.LoggerWithCtx) DiagnosticResult {
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
		return DiagnosticResult{
			CheckName: "Clock Sync",
			Passed:    false,
			Error:     fmt.Errorf("time sync not active"),
		}
	}

	// Check clock skew in Ceph
	cmd := exec.Command("ceph", "health", "detail")
	if output, err := cmd.Output(); err == nil {
		if strings.Contains(string(output), "clock skew") {
			logger.Warn("Clock skew detected between Ceph daemons")
			return DiagnosticResult{
				CheckName: "Clock Sync",
				Passed:    false,
				Error:     fmt.Errorf("clock skew detected"),
			}
		}
	}

	return DiagnosticResult{
		CheckName: "Clock Sync",
		Passed:    true,
	}
}
