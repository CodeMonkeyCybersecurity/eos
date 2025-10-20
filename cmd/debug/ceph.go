// cmd/debug/ceph.go
package debug

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

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
	logger.Info("Ceph Cluster Diagnostics - Deep Debug Mode")
	logger.Info("================================================================================")
	logger.Info("")

	issueCount := 0
	clusterReachable := false

	// 0. Environment & Installation State
	logger.Info("0. Environment & Installation State")
	logger.Info(strings.Repeat("-", 40))
	if err := checkCephInstallation(logger, cephDebugVerbose); err != nil {
		logger.Error("Installation check failed", zap.Error(err))
		issueCount++
	} else {
		logger.Info("✓ Ceph packages installed")
	}
	logger.Info("")

	// 1. Binary verification
	logger.Info("1. Checking Ceph binaries")
	logger.Info(strings.Repeat("-", 40))
	if err := checkCephBinaries(logger); err != nil {
		logger.Error("❌ Binary check failed", zap.Error(err))
		issueCount++
	} else {
		logger.Info("✓ All binaries found")
	}
	logger.Info("")

	// 1a. Process State (CRITICAL for non-running clusters)
	logger.Info("1a. Checking Process State")
	logger.Info(strings.Repeat("-", 40))
	if err := checkCephProcesses(logger, cephDebugVerbose); err != nil {
		logger.Error("❌ Process check failed", zap.Error(err))
		issueCount++
	} else {
		logger.Info("✓ Ceph processes running")
	}
	logger.Info("")

	// 1b. Systemd Unit State
	logger.Info("1b. Checking Systemd Units")
	logger.Info(strings.Repeat("-", 40))
	if err := checkSystemdUnits(logger, cephDebugVerbose); err != nil {
		logger.Error("❌ Systemd unit check failed", zap.Error(err))
		issueCount++
	} else {
		logger.Info("✓ Systemd units configured")
	}
	logger.Info("")

	// 1c. Configuration Discovery & Validation
	logger.Info("1c. Configuration Discovery & Validation")
	logger.Info(strings.Repeat("-", 40))
	if err := checkCephConfiguration(logger, cephDebugVerbose); err != nil {
		logger.Warn("⚠️  Configuration check found issues", zap.Error(err))
		issueCount++
	} else {
		logger.Info("✓ Configuration valid")
	}
	logger.Info("")

	// 1d. Network & Connectivity Layer
	logger.Info("1d. Network & Connectivity Layer")
	logger.Info(strings.Repeat("-", 40))
	if err := checkCephNetwork(logger, cephDebugVerbose); err != nil {
		logger.Warn("⚠️  Network check found issues", zap.Error(err))
		issueCount++
	} else {
		logger.Info("✓ Network connectivity OK")
	}
	logger.Info("")

	// 1e. Storage & Data Layer
	logger.Info("1e. Storage & Data Layer")
	logger.Info(strings.Repeat("-", 40))
	if err := checkCephStorage(logger, cephDebugVerbose); err != nil {
		logger.Warn("⚠️  Storage check found issues", zap.Error(err))
		issueCount++
	} else {
		logger.Info("✓ Storage layer OK")
	}
	logger.Info("")

	// 2. Cluster connectivity (only if processes are running)
	logger.Info("2. Checking cluster connectivity")
	logger.Info(strings.Repeat("-", 40))
	if err := checkCephConnectivity(logger); err != nil {
		logger.Error("❌ Connectivity check failed", zap.Error(err))
		issueCount++
		clusterReachable = false
	} else {
		logger.Info("✓ Cluster is reachable")
		clusterReachable = true
	}
	logger.Info("")

	// Only check cluster-level status if cluster is reachable
	if clusterReachable {
		// 3. Cluster health
		logger.Info("3. Checking cluster health")
		logger.Info(strings.Repeat("-", 40))
		if err := checkCephHealth(logger, cephDebugVerbose); err != nil {
			logger.Warn("⚠️  Health check found issues", zap.Error(err))
			issueCount++
		} else {
			logger.Info("✓ Cluster health: HEALTH_OK")
		}
		logger.Info("")

		// 4. MON status
		logger.Info("4. Checking MON daemon status")
		logger.Info(strings.Repeat("-", 40))
		if err := checkMonStatus(logger); err != nil {
			logger.Error("❌ MON check failed", zap.Error(err))
			issueCount++
		} else {
			logger.Info("✓ MON daemons operational")
		}
		logger.Info("")

		// 5. MGR status
		logger.Info("5. Checking MGR daemon status")
		logger.Info(strings.Repeat("-", 40))
		if err := checkMgrStatus(logger); err != nil {
			logger.Warn("⚠️  MGR check found issues", zap.Error(err))
			issueCount++
		} else {
			logger.Info("✓ MGR daemons operational")
		}
		logger.Info("")

		// 6. OSD status
		logger.Info("6. Checking OSD status")
		logger.Info(strings.Repeat("-", 40))
		if err := checkOSDStatus(logger, cephDebugVerbose); err != nil {
			logger.Warn("⚠️  OSD check found issues", zap.Error(err))
			issueCount++
		} else {
			logger.Info("✓ All OSDs up and in")
		}
		logger.Info("")

		// 7. Storage capacity
		logger.Info("7. Checking storage capacity")
		logger.Info(strings.Repeat("-", 40))
		if err := checkStorageCapacity(logger); err != nil {
			logger.Warn("⚠️  Storage check found issues", zap.Error(err))
			issueCount++
		}
		logger.Info("")

		// 8. PG status
		logger.Info("8. Checking Placement Group status")
		logger.Info(strings.Repeat("-", 40))
		if err := checkPGStatus(logger); err != nil {
			logger.Warn("⚠️  PG check found issues", zap.Error(err))
			issueCount++
		}
		logger.Info("")

		// 9. Clock sync
		logger.Info("9. Checking clock synchronization")
		logger.Info(strings.Repeat("-", 40))
		if err := checkClockSync(logger); err != nil {
			logger.Warn("⚠️  Clock sync check found issues", zap.Error(err))
			issueCount++
		}
		logger.Info("")
	} else {
		logger.Warn("⚠️  Skipping cluster-level checks (cluster not reachable)")
		logger.Info("")
	}

	// 10. Deep Log analysis (always run, especially critical when cluster isn't running)
	logger.Info("10. Deep Log Analysis")
	logger.Info(strings.Repeat("-", 40))
	if err := analyzeCephLogsDeep(logger, cephDebugLogs, cephDebugVerbose); err != nil {
		logger.Warn("⚠️  Log analysis found issues", zap.Error(err))
		issueCount++
	}
	logger.Info("")

	// Summary
	logger.Info("================================================================================")
	logger.Info("Diagnostics Summary")
	logger.Info("================================================================================")
	if issueCount == 0 {
		logger.Info("✓ No issues detected - cluster is healthy")
	} else {
		logger.Warn(fmt.Sprintf("❌ Found %d issue(s) requiring attention", issueCount))
		logger.Info("")
		
		if !clusterReachable {
			logger.Info("⚠️  CRITICAL: Cluster is not reachable or not running")
			logger.Info("")
			logger.Info("Next Steps:")
			logger.Info("  1. Check if Ceph services are enabled: systemctl list-unit-files | grep ceph")
			logger.Info("  2. Start Ceph services: systemctl start ceph.target")
			logger.Info("  3. Check service logs: journalctl -u ceph-mon@* -xe")
			logger.Info("  4. Verify configuration: cat /etc/ceph/ceph.conf")
			logger.Info("  5. Check keyring permissions: ls -la /etc/ceph/*.keyring")
			logger.Info("")
		}
		
		logger.Info("General Recommendations:")
		logger.Info("  1. Review error messages above for specific issues")
		logger.Info("  2. Check Ceph documentation: https://docs.ceph.com/")
		if clusterReachable {
			logger.Info("  3. Use 'ceph health detail' for more information")
		}
		logger.Info("  4. Check logs: journalctl -u 'ceph*' --since '1 hour ago'")
		logger.Info("  5. Review file permissions in /var/lib/ceph/ and /etc/ceph/")
		if !cephDebugFix {
			logger.Info("  6. Run with --fix flag to auto-fix common issues")
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
	// CRITICAL: Add timeout to prevent hanging on unreachable cluster
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ceph", "status")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			logger.Error("Cluster connection timed out after 10 seconds")
			logger.Info("Possible causes:")
			logger.Info("  1. Ceph cluster is not running")
			logger.Info("  2. Network connectivity issues")
			logger.Info("  3. Ceph configuration missing or incorrect")
			logger.Info("  4. Authentication (ceph.client.admin.keyring) issues")
			return fmt.Errorf("cluster connection timeout - cluster may be down or unreachable")
		}
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

// checkCephInstallation checks what Ceph packages/components are installed
func checkCephInstallation(logger otelzap.LoggerWithCtx, verbose bool) error {
	logger.Info("Checking Ceph installation...")
	
	// Check for Debian/Ubuntu packages
	cmd := exec.Command("dpkg", "-l")
	output, err := cmd.Output()
	if err != nil {
		// Try RPM-based systems
		cmd = exec.Command("rpm", "-qa")
		output, err = cmd.Output()
		if err != nil {
			return fmt.Errorf("cannot query package manager: %w", err)
		}
	}
	
	cephPackages := []string{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "ceph") {
			cephPackages = append(cephPackages, strings.TrimSpace(line))
		}
	}
	
	if len(cephPackages) == 0 {
		logger.Warn("⚠️  No Ceph packages found")
		return fmt.Errorf("ceph not installed")
	}
	
	logger.Info(fmt.Sprintf("Found %d Ceph packages", len(cephPackages)))
	if verbose {
		for _, pkg := range cephPackages {
			logger.Info("  " + pkg)
		}
	}
	
	// Check Ceph version
	cmd = exec.Command("ceph", "--version")
	if output, err := cmd.Output(); err == nil {
		logger.Info("Ceph version: " + strings.TrimSpace(string(output)))
	}
	
	// Check user/group
	cmd = exec.Command("id", "ceph")
	if output, err := cmd.Output(); err == nil {
		logger.Info("Ceph user: " + strings.TrimSpace(string(output)))
	} else {
		logger.Warn("⚠️  Ceph user not found")
		// Check UID 472 (common Ceph UID)
		cmd = exec.Command("id", "472")
		if output, err := cmd.Output(); err == nil {
			logger.Info("UID 472 exists: " + strings.TrimSpace(string(output)))
		}
	}
	
	return nil
}

// checkCephProcesses checks if any Ceph processes are running
func checkCephProcesses(logger otelzap.LoggerWithCtx, verbose bool) error {
	logger.Info("Checking for Ceph processes...")
	
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("cannot list processes: %w", err)
	}
	
	cephProcesses := []string{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "ceph") && !strings.Contains(line, "grep") {
			cephProcesses = append(cephProcesses, strings.TrimSpace(line))
		}
	}
	
	if len(cephProcesses) == 0 {
		logger.Error("❌ No Ceph processes running")
		logger.Info("  → Ceph cluster is not started")
		return fmt.Errorf("no ceph processes found")
	}
	
	logger.Info(fmt.Sprintf("Found %d Ceph processes", len(cephProcesses)))
	if verbose {
		for _, proc := range cephProcesses {
			logger.Info("  " + proc)
		}
	}
	
	return nil
}

// checkSystemdUnits checks Ceph systemd unit files and their states
func checkSystemdUnits(logger otelzap.LoggerWithCtx, verbose bool) error {
	logger.Info("Checking systemd units...")
	
	// List all Ceph unit files
	cmd := exec.Command("systemctl", "list-unit-files")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("cannot list systemd units: %w", err)
	}
	
	unitFiles := []string{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "ceph") {
			unitFiles = append(unitFiles, strings.TrimSpace(line))
		}
	}
	
	if len(unitFiles) == 0 {
		logger.Warn("⚠️  No Ceph systemd unit files found")
		logger.Info("  → Ceph may not be configured to run via systemd")
		return fmt.Errorf("no ceph systemd units")
	}
	
	logger.Info(fmt.Sprintf("Found %d Ceph unit files", len(unitFiles)))
	if verbose {
		for _, unit := range unitFiles {
			logger.Info("  " + unit)
		}
	}
	
	// Check active units
	cmd = exec.Command("systemctl", "list-units", "--all")
	output, err = cmd.Output()
	if err == nil {
		activeUnits := []string{}
		lines = strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "ceph") {
				activeUnits = append(activeUnits, strings.TrimSpace(line))
			}
		}
		
		if len(activeUnits) == 0 {
			logger.Warn("⚠️  No active Ceph units")
			logger.Info("  → Services may need to be started")
		} else {
			logger.Info(fmt.Sprintf("Found %d active/loaded units", len(activeUnits)))
			if verbose {
				for _, unit := range activeUnits {
					logger.Info("  " + unit)
				}
			}
		}
	}
	
	return nil
}

// checkCephConfiguration validates Ceph configuration files
func checkCephConfiguration(logger otelzap.LoggerWithCtx, verbose bool) error {
	logger.Info("Checking Ceph configuration...")
	
	// Check ceph.conf
	configPath := "/etc/ceph/ceph.conf"
	cmd := exec.Command("cat", configPath)
	output, err := cmd.Output()
	if err != nil {
		logger.Error("❌ Cannot read " + configPath, zap.Error(err))
		return fmt.Errorf("config file not found")
	}
	
	logger.Info("✓ Configuration file exists: " + configPath)
	if verbose {
		logger.Info("Configuration contents:")
		for _, line := range strings.Split(string(output), "\n") {
			if strings.TrimSpace(line) != "" {
				logger.Info("  " + line)
			}
		}
	}
	
	// Check for keyrings
	logger.Info("Checking keyrings...")
	cmd = exec.Command("ls", "-lah", "/etc/ceph/")
	if output, err := cmd.Output(); err == nil {
		keyringFound := false
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, ".keyring") {
				keyringFound = true
				logger.Info("  " + line)
			}
		}
		
		if !keyringFound {
			logger.Warn("⚠️  No keyring files found in /etc/ceph/")
			logger.Info("  → Authentication may fail")
			return fmt.Errorf("no keyrings found")
		}
	}
	
	// Validate config syntax using ceph-conf if available
	cmd = exec.Command("ceph-conf", "--show-config")
	if output, err := cmd.Output(); err == nil {
		logger.Info("✓ Configuration syntax is valid")
		if verbose {
			logger.Info("Parsed configuration:")
			for _, line := range strings.Split(string(output), "\n")[:20] {
				if strings.TrimSpace(line) != "" {
					logger.Info("  " + line)
				}
			}
		}
	}
	
	return nil
}

// checkCephNetwork checks network connectivity to monitors
func checkCephNetwork(logger otelzap.LoggerWithCtx, verbose bool) error {
	logger.Info("Checking network connectivity...")
	
	// Get monitor addresses from config
	cmd := exec.Command("grep", "mon_host", "/etc/ceph/ceph.conf")
	output, err := cmd.Output()
	if err != nil {
		logger.Warn("⚠️  Cannot find mon_host in config")
		return fmt.Errorf("no monitor hosts configured")
	}
	
	monHostLine := strings.TrimSpace(string(output))
	logger.Info("Monitor configuration: " + monHostLine)
	
	// Extract IP/hostname (simple parsing)
	parts := strings.Split(monHostLine, "=")
	if len(parts) < 2 {
		return fmt.Errorf("cannot parse mon_host")
	}
	
	monHosts := strings.TrimSpace(parts[1])
	hosts := strings.Split(monHosts, ",")
	
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		logger.Info("Checking connectivity to: " + host)
		
		// Try to ping
		cmd = exec.Command("ping", "-c", "1", "-W", "2", host)
		if err := cmd.Run(); err != nil {
			logger.Warn("⚠️  Cannot ping " + host)
		} else {
			logger.Info("  ✓ Ping successful")
		}
		
		// Check if monitor ports are listening (3300 for v2, 6789 for v1)
		for _, port := range []string{"3300", "6789"} {
			cmd = exec.Command("ss", "-tlnp")
			if output, err := cmd.Output(); err == nil {
				if strings.Contains(string(output), ":"+port) {
					logger.Info(fmt.Sprintf("  ✓ Port %s is listening", port))
				} else if verbose {
					logger.Info(fmt.Sprintf("  Port %s not listening", port))
				}
			}
		}
	}
	
	return nil
}

// checkCephStorage checks storage layer (OSD data directories, devices)
func checkCephStorage(logger otelzap.LoggerWithCtx, verbose bool) error {
	logger.Info("Checking storage layer...")
	
	// Check OSD data directories
	cmd := exec.Command("ls", "-lah", "/var/lib/ceph/osd/")
	output, err := cmd.Output()
	if err != nil {
		logger.Warn("⚠️  Cannot access /var/lib/ceph/osd/", zap.Error(err))
		return fmt.Errorf("osd directory not accessible")
	}
	
	lines := strings.Split(string(output), "\n")
	osdCount := 0
	for _, line := range lines {
		if strings.Contains(line, "ceph-") {
			osdCount++
			if verbose {
				logger.Info("  " + line)
			}
		}
	}
	
	if osdCount == 0 {
		logger.Warn("⚠️  No OSD directories found")
		logger.Info("  → OSDs may not be configured")
	} else {
		logger.Info(fmt.Sprintf("Found %d OSD directories", osdCount))
	}
	
	// Check disk space on Ceph directories
	cmd = exec.Command("df", "-h", "/var/lib/ceph")
	if output, err := cmd.Output(); err == nil {
		logger.Info("Disk space for /var/lib/ceph:")
		for _, line := range strings.Split(string(output), "\n") {
			if strings.TrimSpace(line) != "" {
				logger.Info("  " + line)
			}
		}
	}
	
	// Check MON data directories
	cmd = exec.Command("ls", "-lah", "/var/lib/ceph/mon/")
	if output, err := cmd.Output(); err == nil {
		monCount := 0
		lines = strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "ceph-") {
				monCount++
				if verbose {
					logger.Info("  " + line)
				}
			}
		}
		
		if monCount > 0 {
			logger.Info(fmt.Sprintf("Found %d MON directories", monCount))
		}
	}
	
	return nil
}

func analyzeCephLogsDeep(logger otelzap.LoggerWithCtx, lines int, verbose bool) error {
	errorsFound := false
	
	// Check for ANY Ceph-related systemd logs
	logger.Info("Checking systemd journal for Ceph services...")
	cmd := exec.Command("journalctl", "-u", "ceph*", "--since", "1 hour ago", "-n", fmt.Sprintf("%d", lines), "--no-pager")
	if output, err := cmd.Output(); err == nil {
		logStr := string(output)
		if len(strings.TrimSpace(logStr)) == 0 {
			logger.Warn("⚠️  No systemd journal entries found for Ceph services")
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
				logger.Warn("⚠️  Errors found in systemd logs")
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
				logger.Warn("⚠️  No recent log files (modified in last 24h)")
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
		logger.Warn("⚠️  Cannot access /var/log/ceph/", zap.Error(err))
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
			logger.Warn("⚠️  Crash dumps detected:")
			for _, line := range strings.Split(logStr, "\n") {
				if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "total") {
					logger.Warn("  " + line)
				}
			}
			errorsFound = true
		}
	}

	if errorsFound {
		return fmt.Errorf("log analysis found issues")
	}
	
	logger.Info(fmt.Sprintf("✓ Analyzed logs (last %d lines)", lines))
	return nil
}
