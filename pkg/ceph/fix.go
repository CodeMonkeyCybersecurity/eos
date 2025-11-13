// pkg/ceph/fix.go
package ceph

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// FixOptions contains options for running fixes
type FixOptions struct {
	DryRun          bool // Preview fixes without applying
	PermissionsOnly bool // Only fix permissions, not services
	BootstrapMon    bool // Bootstrap monitor if needed
	RestartServices bool // Restart services after fixes
}

// FixResult represents the result of a fix operation
type FixResult struct {
	FixName     string
	Applied     bool
	Success     bool
	Error       error
	Details     string
	CommandsRun []string
}

// FixEngine applies automated corrections to Ceph drift
type FixEngine struct {
	rc      *eos_io.RuntimeContext
	logger  otelzap.LoggerWithCtx
	opts    FixOptions
	results []FixResult
}

// NewFixEngine creates a new fix engine
func NewFixEngine(rc *eos_io.RuntimeContext, opts FixOptions) *FixEngine {
	return &FixEngine{
		rc:      rc,
		logger:  otelzap.Ctx(rc.Ctx),
		opts:    opts,
		results: []FixResult{},
	}
}

// RunFixes executes all applicable fixes based on diagnostics
func (f *FixEngine) RunFixes() ([]FixResult, error) {
	f.logger.Info("================================================================================")
	if f.opts.DryRun {
		f.logger.Info("Ceph Fix Engine - DRY RUN MODE (no changes will be made)")
	} else {
		f.logger.Info("Ceph Fix Engine - Applying Drift Corrections")
	}
	f.logger.Info("================================================================================")
	f.logger.Info("")

	// Run diagnostics first to identify issues
	f.logger.Info("Step 1: Running diagnostics to identify issues...")
	diagOpts := DiagnosticOptions{
		Verbose: false,
		Fix:     false,
	}
	results, _ := RunFullDiagnostics(f.logger, diagOpts)

	// Extract issues from diagnostic results
	var criticalIssues []Issue
	var warnings []Issue

	for _, result := range results {
		for _, issue := range result.Issues {
			switch issue.Severity {
			case "critical":
				criticalIssues = append(criticalIssues, issue)
			case "warning":
				warnings = append(warnings, issue)
			}
		}
	}

	f.logger.Info(fmt.Sprintf("Found %d critical issue(s) and %d warning(s)", len(criticalIssues), len(warnings)))
	f.logger.Info("")

	// Fix critical issues first
	if len(criticalIssues) > 0 {
		f.logger.Info("Step 2: Fixing critical issues...")
		for i, issue := range criticalIssues {
			f.logger.Info(fmt.Sprintf("  [%d/%d] %s: %s", i+1, len(criticalIssues), issue.Component, issue.Description))
			f.applyIssueFix(issue)
		}
		f.logger.Info("")
	}

	// Fix warnings if requested
	if !f.opts.PermissionsOnly && len(warnings) > 0 {
		f.logger.Info("Step 3: Fixing warnings...")
		for i, issue := range warnings {
			f.logger.Info(fmt.Sprintf("  [%d/%d] %s: %s", i+1, len(warnings), issue.Component, issue.Description))
			f.applyIssueFix(issue)
		}
		f.logger.Info("")
	}

	// Verify fixes if not dry run
	if !f.opts.DryRun {
		f.logger.Info("Step 4: Verifying fixes...")
		f.verifyFixes()
		f.logger.Info("")
	}

	// Summary
	f.logger.Info("================================================================================")
	f.logger.Info("Fix Summary")
	f.logger.Info("================================================================================")

	successCount := 0
	skippedCount := 0
	failedCount := 0

	for _, result := range f.results {
		if !result.Applied {
			skippedCount++
		} else if result.Success {
			successCount++
		} else {
			failedCount++
		}
	}

	if f.opts.DryRun {
		f.logger.Info(fmt.Sprintf("DRY RUN: Would apply %d fix(es)", len(f.results)))
	} else {
		f.logger.Info(fmt.Sprintf("✓ Successfully applied: %d fix(es)", successCount))
		if failedCount > 0 {
			f.logger.Warn(fmt.Sprintf("✗ Failed: %d fix(es)", failedCount))
		}
		if skippedCount > 0 {
			f.logger.Info(fmt.Sprintf("⊙ Skipped: %d fix(es)", skippedCount))
		}
	}

	f.logger.Info("")

	// Show detailed results
	for _, result := range f.results {
		status := "✓"
		if !result.Applied {
			status = "⊙"
		} else if !result.Success {
			status = "✗"
		}

		f.logger.Info(fmt.Sprintf("%s %s", status, result.FixName))
		if result.Details != "" {
			f.logger.Info(fmt.Sprintf("  → %s", result.Details))
		}
		if result.Error != nil {
			f.logger.Error(fmt.Sprintf("  Error: %v", result.Error))
		}
		if len(result.CommandsRun) > 0 && !f.opts.DryRun {
			for _, cmd := range result.CommandsRun {
				f.logger.Debug(fmt.Sprintf("  Ran: %s", cmd))
			}
		}
	}

	return f.results, nil
}

// applyIssueFix applies a fix for a specific issue
func (f *FixEngine) applyIssueFix(issue Issue) {
	switch issue.Component {
	case "ceph-mon":
		f.fixMonitor(issue)
	case "ceph-mgr":
		f.fixManager(issue)
	case "ceph":
		f.fixGeneral(issue)
	case "systemd":
		f.fixSystemd(issue)
	default:
		f.logger.Debug(fmt.Sprintf("No automated fix available for component: %s", issue.Component))
	}
}

// fixMonitor fixes monitor-related issues
func (f *FixEngine) fixMonitor(issue Issue) {
	// Check if it's a bootstrap issue
	if strings.Contains(issue.Description, "never bootstrapped") {
		f.bootstrapMonitor()
	} else if strings.Contains(issue.Description, "not running") {
		f.startMonitorService()
	} else if strings.Contains(issue.Description, "not enabled") {
		f.enableMonitorService()
	}
}

// bootstrapMonitor initializes the monitor if it was never bootstrapped
// Uses the new complete bootstrap implementation from bootstrap.go
func (f *FixEngine) bootstrapMonitor() {
	result := FixResult{
		FixName:     "Bootstrap Ceph Monitor",
		Applied:     false,
		CommandsRun: []string{},
	}

	if !f.opts.BootstrapMon {
		result.Details = "Skipped (use --bootstrap-mon to enable automatic bootstrap)"
		f.logger.Info("")
		f.logger.Info("╔════════════════════════════════════════════════════════════════╗")
		f.logger.Info("║  CRITICAL: Monitor Bootstrap Required                          ║")
		f.logger.Info("╚════════════════════════════════════════════════════════════════╝")
		f.logger.Info("")
		f.logger.Info("The monitor on this host was never initialized.")
		f.logger.Info("This is a NEW cluster that needs proper bootstrap.")
		f.logger.Info("")
		f.logger.Info("To bootstrap safely, you need to provide:")
		f.logger.Info("  • Monitor IP address")
		f.logger.Info("  • Public network CIDR (e.g., 192.168.1.0/24)")
		f.logger.Info("")
		f.logger.Info("Run with bootstrap flag:")
		f.logger.Info("  sudo eos update ceph --fix --bootstrap-mon")
		f.logger.Info("")
		f.results = append(f.results, result)
		return
	}

	if f.opts.DryRun {
		result.Applied = true
		result.Success = true
		result.Details = "Would bootstrap monitor using complete Ceph bootstrap process (9 steps)"
		result.CommandsRun = []string{
			"Pre-flight validation checks",
			"Generate cluster FSID (UUID)",
			"Create /etc/ceph/ceph.conf with fsid",
			"Create monitor, admin, and bootstrap keyrings",
			"Generate monmap",
			"Initialize monitor database (ceph-mon --mkfs)",
			"Fix ownership and permissions",
			"Start monitor service",
			"Verify monitor health",
		}
		f.results = append(f.results, result)
		return
	}

	// INTERVENE: Use the complete bootstrap implementation
	result.Applied = true

	f.logger.Info("")
	f.logger.Info("╔════════════════════════════════════════════════════════════════╗")
	f.logger.Info("║  Starting Complete Monitor Bootstrap Process                   ║")
	f.logger.Info("╚════════════════════════════════════════════════════════════════╝")
	f.logger.Info("")
	f.logger.Info("This will create a NEW Ceph cluster with proper configuration.")
	f.logger.Info("")

	// Gather bootstrap configuration
	hostname, err := os.Hostname()
	if err != nil {
		result.Error = fmt.Errorf("failed to get hostname: %w", err)
		f.results = append(f.results, result)
		return
	}

	// Try to read existing ceph.conf for network settings
	var monitorIP, publicNetwork string
	if config, err := ReadCephConf(f.logger); err == nil {
		monitorIP = config.Global.MonHost
		publicNetwork = config.Global.PublicNetwork
		f.logger.Info("Found existing ceph.conf, using network settings from it")
	}

	// If not in ceph.conf, we need to detect or prompt
	if monitorIP == "" || publicNetwork == "" {
		// Try to detect from network interfaces
		f.logger.Warn("Network configuration not found in ceph.conf")
		f.logger.Warn("Bootstrap requires monitor IP and public network CIDR")
		result.Error = fmt.Errorf("cannot auto-detect network configuration - please ensure /etc/ceph/ceph.conf has 'mon host' and 'public network' configured, or use interactive bootstrap")
		f.results = append(f.results, result)
		return
	}

	// Create bootstrap configuration
	bootstrapConfig := &BootstrapConfig{
		Hostname:       hostname,
		MonitorIP:      monitorIP,
		PublicNetwork:  publicNetwork,
		ClusterNetwork: publicNetwork, // Use same network for single-host
		ClusterName:    "ceph",
	}

	f.logger.Info("Bootstrap configuration:",
		zap.String("hostname", bootstrapConfig.Hostname),
		zap.String("monitor_ip", bootstrapConfig.MonitorIP),
		zap.String("public_network", bootstrapConfig.PublicNetwork))
	f.logger.Info("")

	// Execute bootstrap
	if err := BootstrapFirstMonitor(f.rc, bootstrapConfig); err != nil {
		result.Error = fmt.Errorf("bootstrap failed: %w", err)
		result.Success = false
		f.results = append(f.results, result)
		return
	}

	result.Success = true
	result.Details = fmt.Sprintf("Successfully bootstrapped monitor on %s (FSID: %s)", hostname, bootstrapConfig.FSID)
	result.CommandsRun = []string{
		"Completed full 9-step Ceph bootstrap process",
		"See logs above for detailed steps",
	}
	f.results = append(f.results, result)
}

// startMonitorService starts the monitor service
func (f *FixEngine) startMonitorService() {
	result := FixResult{
		FixName:     "Start Monitor Service",
		Applied:     true,
		CommandsRun: []string{},
	}

	hostname, err := os.Hostname()
	if err != nil {
		result.Error = err
		result.Success = false
		f.results = append(f.results, result)
		return
	}

	serviceName := fmt.Sprintf("ceph-mon@%s", hostname)

	if f.opts.DryRun {
		result.Success = true
		result.Details = fmt.Sprintf("Would start service: %s", serviceName)
		result.CommandsRun = []string{fmt.Sprintf("systemctl start %s", serviceName)}
		f.results = append(f.results, result)
		return
	}

	cmd := exec.Command("systemctl", "start", serviceName)
	output, err := cmd.CombinedOutput()
	result.CommandsRun = append(result.CommandsRun, cmd.String())

	if err != nil {
		result.Error = fmt.Errorf("failed to start service: %s", output)
		result.Success = false
	} else {
		result.Success = true
		result.Details = fmt.Sprintf("Started %s", serviceName)
	}

	f.results = append(f.results, result)
}

// enableMonitorService enables the monitor service
func (f *FixEngine) enableMonitorService() {
	result := FixResult{
		FixName:     "Enable Monitor Service",
		Applied:     true,
		CommandsRun: []string{},
	}

	hostname, err := os.Hostname()
	if err != nil {
		result.Error = err
		result.Success = false
		f.results = append(f.results, result)
		return
	}

	serviceName := fmt.Sprintf("ceph-mon@%s", hostname)

	if f.opts.DryRun {
		result.Success = true
		result.Details = fmt.Sprintf("Would enable service: %s", serviceName)
		result.CommandsRun = []string{fmt.Sprintf("systemctl enable %s", serviceName)}
		f.results = append(f.results, result)
		return
	}

	cmd := exec.Command("systemctl", "enable", serviceName)
	output, err := cmd.CombinedOutput()
	result.CommandsRun = append(result.CommandsRun, cmd.String())

	if err != nil {
		result.Error = fmt.Errorf("failed to enable service: %s", output)
		result.Success = false
	} else {
		result.Success = true
		result.Details = fmt.Sprintf("Enabled %s (will start on boot)", serviceName)
	}

	f.results = append(f.results, result)
}

// fixManager fixes manager-related issues
func (f *FixEngine) fixManager(issue Issue) {
	if strings.Contains(issue.Description, "not running") {
		// Start manager service
		result := FixResult{
			FixName: "Start Manager Service",
			Applied: true,
		}

		if f.opts.DryRun {
			result.Success = true
			result.Details = "Would start ceph-mgr.target"
			result.CommandsRun = []string{"systemctl start ceph-mgr.target"}
		} else {
			cmd := exec.Command("systemctl", "start", "ceph-mgr.target")
			_, err := cmd.CombinedOutput()
			result.CommandsRun = []string{cmd.String()}
			result.Success = (err == nil)
			if err != nil {
				result.Error = err
			}
		}

		f.results = append(f.results, result)
	}
}

// fixGeneral fixes general Ceph issues
func (f *FixEngine) fixGeneral(issue Issue) {
	if strings.Contains(issue.Description, "No Ceph processes") {
		// Start ceph.target
		result := FixResult{
			FixName: "Start Ceph Services",
			Applied: true,
		}

		if f.opts.DryRun {
			result.Success = true
			result.Details = "Would start ceph.target"
			result.CommandsRun = []string{"systemctl start ceph.target"}
		} else {
			cmd := exec.Command("systemctl", "start", "ceph.target")
			_, err := cmd.CombinedOutput()
			result.CommandsRun = []string{cmd.String()}
			result.Success = (err == nil)
			if err != nil {
				result.Error = err
			} else {
				result.Details = "Started Ceph services"
			}
		}

		f.results = append(f.results, result)
	}
}

// fixSystemd fixes systemd-related issues
func (f *FixEngine) fixSystemd(issue Issue) {
	if strings.Contains(issue.Description, "not enabled") {
		// Enable ceph.target
		result := FixResult{
			FixName: "Enable Ceph Target",
			Applied: true,
		}

		if f.opts.DryRun {
			result.Success = true
			result.Details = "Would enable ceph.target"
			result.CommandsRun = []string{"systemctl enable ceph.target"}
		} else {
			cmd := exec.Command("systemctl", "enable", "ceph.target")
			_, err := cmd.CombinedOutput()
			result.CommandsRun = []string{cmd.String()}
			result.Success = (err == nil)
			if err != nil {
				result.Error = err
			}
		}

		f.results = append(f.results, result)
	}
}

// verifyFixes runs diagnostics again to verify fixes were successful
func (f *FixEngine) verifyFixes() {
	f.logger.Info("Re-running diagnostics to verify fixes...")

	diagOpts := DiagnosticOptions{
		Verbose: false,
		Fix:     false,
	}

	results, _ := RunFullDiagnostics(f.logger, diagOpts)

	criticalIssues := 0
	for _, result := range results {
		for _, issue := range result.Issues {
			if issue.Severity == "critical" {
				criticalIssues++
			}
		}
	}

	if criticalIssues == 0 {
		f.logger.Info("✓ Verification passed: No critical issues remaining")
	} else {
		f.logger.Warn(fmt.Sprintf("  Verification: %d critical issue(s) still remain", criticalIssues))
		f.logger.Info("  → Some issues may require manual intervention")
		f.logger.Info("  → Run 'eos debug ceph' for detailed diagnostics")
	}
}
