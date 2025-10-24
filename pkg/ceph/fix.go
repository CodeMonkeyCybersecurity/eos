// pkg/ceph/fix.go
package ceph

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
func (f *FixEngine) bootstrapMonitor() {
	result := FixResult{
		FixName:     "Bootstrap Ceph Monitor",
		Applied:     false,
		CommandsRun: []string{},
	}

	if !f.opts.BootstrapMon {
		result.Details = "Skipped (use --bootstrap-mon to enable automatic bootstrap)"
		f.results = append(f.results, result)
		return
	}

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		result.Error = fmt.Errorf("failed to get hostname: %w", err)
		f.results = append(f.results, result)
		return
	}

	monDataDir := filepath.Join("/var/lib/ceph/mon", fmt.Sprintf("ceph-%s", hostname))

	// ASSESS: Check if monitor data directory exists
	if _, err := os.Stat(monDataDir); err == nil {
		result.Details = "Monitor data directory already exists, skipping bootstrap"
		f.results = append(f.results, result)
		return
	}

	if f.opts.DryRun {
		result.Applied = true
		result.Success = true
		result.Details = fmt.Sprintf("Would bootstrap monitor for host %s", hostname)
		result.CommandsRun = []string{
			"ceph-authtool --create-keyring /tmp/ceph.mon.keyring --gen-key -n mon.",
			fmt.Sprintf("ceph-mon --mkfs -i %s --keyring /tmp/ceph.mon.keyring", hostname),
			fmt.Sprintf("systemctl enable ceph-mon@%s", hostname),
			fmt.Sprintf("systemctl start ceph-mon@%s", hostname),
		}
		f.results = append(f.results, result)
		return
	}

	// INTERVENE: Bootstrap the monitor
	result.Applied = true

	// Step 1: Create keyring
	f.logger.Info("  Creating monitor keyring...")
	cmd := exec.Command("ceph-authtool", "--create-keyring", "/tmp/ceph.mon.keyring", "--gen-key", "-n", "mon.")
	output, err := cmd.CombinedOutput()
	result.CommandsRun = append(result.CommandsRun, cmd.String())
	if err != nil {
		result.Error = fmt.Errorf("failed to create keyring: %s", output)
		f.results = append(f.results, result)
		return
	}

	// Step 2: Initialize monitor database
	f.logger.Info("  Initializing monitor database...")
	cmd = exec.Command("ceph-mon", "--mkfs", "-i", hostname, "--keyring", "/tmp/ceph.mon.keyring")
	output, err = cmd.CombinedOutput()
	result.CommandsRun = append(result.CommandsRun, cmd.String())
	if err != nil {
		result.Error = fmt.Errorf("failed to initialize monitor: %s", output)
		f.results = append(f.results, result)
		return
	}

	// Step 3: Enable service
	f.logger.Info("  Enabling monitor service...")
	serviceName := fmt.Sprintf("ceph-mon@%s", hostname)
	cmd = exec.Command("systemctl", "enable", serviceName)
	_, err = cmd.CombinedOutput()
	result.CommandsRun = append(result.CommandsRun, cmd.String())
	if err != nil {
		f.logger.Warn("Failed to enable service (may already be enabled)", zap.Error(err))
	}

	// Step 4: Start service
	f.logger.Info("  Starting monitor service...")
	cmd = exec.Command("systemctl", "start", serviceName)
	output, err = cmd.CombinedOutput()
	result.CommandsRun = append(result.CommandsRun, cmd.String())
	if err != nil {
		result.Error = fmt.Errorf("failed to start monitor: %s", output)
		f.results = append(f.results, result)
		return
	}

	result.Success = true
	result.Details = fmt.Sprintf("Successfully bootstrapped and started monitor on %s", hostname)
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
		f.logger.Warn(fmt.Sprintf("⚠️  Verification: %d critical issue(s) still remain", criticalIssues))
		f.logger.Info("  → Some issues may require manual intervention")
		f.logger.Info("  → Run 'eos debug ceph' for detailed diagnostics")
	}
}
