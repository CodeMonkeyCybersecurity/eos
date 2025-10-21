// pkg/consul/fix/fix.go
// Consul repair and fix operations following Assess → Intervene → Evaluate pattern

package fix

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/debug"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/scripts"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Config holds the fix configuration options
type Config struct {
	DryRun          bool
	PermissionsOnly bool
	SkipRestart     bool
}

// FixResult holds the results of a fix operation
type FixResult struct {
	Operation   string
	Success     bool
	Message     string
	Details     []string
	ChangesMade bool
}

// RunFixes performs Consul repairs following Assess → Intervene → Evaluate pattern
func RunFixes(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Consul fix operations",
		zap.Bool("dry_run", config.DryRun),
		zap.Bool("permissions_only", config.PermissionsOnly))

	results := []FixResult{}

	// ASSESS - Check what needs fixing
	logger.Info("=== ASSESS PHASE: Checking for issues ===")

	permResult := assessPermissions(rc)
	results = append(results, permResult)

	configIssues := false
	if !config.PermissionsOnly {
		// Run debug diagnostics to assess configuration
		debugConfig := &debug.Config{
			AutoFix:       false, // We'll handle fixes ourselves
			KillProcesses: false,
			TestStart:     false,
			MinimalConfig: false,
			LogLines:      50,
		}

		// Run diagnostics to assess state (but don't apply fixes yet)
		if err := debug.RunDiagnostics(rc, debugConfig); err != nil {
			logger.Warn("Diagnostics found issues",
				zap.Error(err))
			configIssues = true
		}
	}

	// INTERVENE - Apply fixes
	if !config.DryRun {
		logger.Info("=== INTERVENE PHASE: Applying fixes ===")

		// Fix permissions
		if !permResult.Success || permResult.ChangesMade {
			fixPermResult := fixPermissions(rc)
			results = append(results, fixPermResult)
		}

		// Fix missing helper script (P0 - causes watch handler errors)
		helperResult := fixHelperScript(rc)
		results = append(results, helperResult)

		// Fix configuration issues if not permissions-only mode
		if !config.PermissionsOnly && configIssues {
			fixConfigResult := fixConfiguration(rc)
			results = append(results, fixConfigResult)
		}

		// Restart service if changes were made
		changesMade := false
		for _, result := range results {
			if result.ChangesMade {
				changesMade = true
				break
			}
		}

		if changesMade && !config.SkipRestart {
			restartResult := restartConsulService(rc)
			results = append(results, restartResult)
		}
	} else {
		logger.Info("=== DRY RUN MODE: Showing what would be fixed ===")
	}

	// EVALUATE - Display results
	logger.Info("=== EVALUATE PHASE: Fix Summary ===")
	displayResults(rc, results, config.DryRun)

	// Check if any critical issues remain
	hasErrors := false
	for _, result := range results {
		if !result.Success {
			hasErrors = true
			break
		}
	}

	if hasErrors {
		logger.Warn("Consul fix completed with some failures")
		return fmt.Errorf("some fix operations failed - check output above")
	}

	logger.Info("Consul fix completed successfully")
	return nil
}

// assessPermissions checks if permissions need fixing
func assessPermissions(rc *eos_io.RuntimeContext) FixResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Assessing file permissions")

	result := FixResult{
		Operation: "Permission Assessment",
		Success:   true,
		Details:   []string{},
	}

	paths := []string{
		"/etc/consul.d/consul.hcl",
		"/etc/consul.d",
		"/var/lib/consul",
		"/opt/consul",
	}

	// Get consul user/group IDs
	consulUser, err := user.Lookup("consul")
	if err != nil {
		result.Success = false
		result.Message = "consul user does not exist"
		return result
	}

	expectedUID, _ := strconv.Atoi(consulUser.Uid)
	expectedGID, _ := strconv.Atoi(consulUser.Gid)

	issuesFound := 0
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("✗ %s: NOT FOUND", path))
			issuesFound++
			continue
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		ownerOK := stat.Uid == uint32(expectedUID) && stat.Gid == uint32(expectedGID)
		permsOK := true

		// Check expected permissions
		if info.IsDir() {
			// Directories should be 0750
			permsOK = info.Mode().Perm() == 0750
		} else {
			// Files should be 0640
			permsOK = info.Mode().Perm() == 0640
		}

		if !ownerOK || !permsOK {
			result.Details = append(result.Details,
				fmt.Sprintf("✗ %s: owner=%d:%d (expected %d:%d), mode=%04o (expected %04o)",
					path, stat.Uid, stat.Gid, expectedUID, expectedGID,
					info.Mode().Perm(), getExpectedPerms(info.IsDir())))
			issuesFound++
			result.ChangesMade = true
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("✓ %s: OK", path))
		}
	}

	if issuesFound > 0 {
		result.Message = fmt.Sprintf("Found %d permission issue(s) that need fixing", issuesFound)
	} else {
		result.Message = "All permissions are correct"
	}

	return result
}

// fixHelperScript creates the consul-vault-helper script if missing
func fixHelperScript(rc *eos_io.RuntimeContext) FixResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking for consul-vault-helper script")

	result := FixResult{
		Operation: "Helper Script Fix",
		Success:   true,
		Details:   []string{},
	}

	scriptPath := "/usr/local/bin/consul-vault-helper"

	// ASSESS - Check if script exists
	if _, err := os.Stat(scriptPath); err == nil {
		result.Message = "Helper script already exists"
		result.Details = append(result.Details, fmt.Sprintf("✓ %s: exists", scriptPath))
		result.ChangesMade = false
		return result
	}

	// INTERVENE - Create the script
	logger.Info("Creating missing consul-vault-helper script")
	if err := scripts.CreateHelper(rc); err != nil {
		result.Success = false
		result.Message = "Failed to create helper script"
		result.Details = append(result.Details, fmt.Sprintf("✗ Error: %v", err))
		return result
	}

	// EVALUATE - Verify creation
	if _, err := os.Stat(scriptPath); err != nil {
		result.Success = false
		result.Message = "Helper script creation failed verification"
		result.Details = append(result.Details, fmt.Sprintf("✗ %s: not found after creation", scriptPath))
		return result
	}

	result.Message = "Helper script created successfully"
	result.Details = append(result.Details, fmt.Sprintf("✓ %s: created", scriptPath))
	result.ChangesMade = true

	return result
}

// fixPermissions repairs file and directory permissions
func fixPermissions(rc *eos_io.RuntimeContext) FixResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Fixing file permissions and ownership")

	result := FixResult{
		Operation:   "Permission Fix",
		Success:     true,
		ChangesMade: true,
		Details:     []string{},
	}

	paths := map[string]struct {
		isDir bool
		perms os.FileMode
	}{
		"/etc/consul.d/consul.hcl": {isDir: false, perms: 0640},
		"/etc/consul.d":            {isDir: true, perms: 0750},
		"/var/lib/consul":          {isDir: true, perms: 0750},
		"/opt/consul":              {isDir: true, perms: 0755},
	}

	// Get consul user/group IDs
	consulUser, err := user.Lookup("consul")
	if err != nil {
		result.Success = false
		result.Message = "consul user does not exist - cannot fix permissions"
		return result
	}

	uid, _ := strconv.Atoi(consulUser.Uid)
	gid, _ := strconv.Atoi(consulUser.Gid)

	fixCount := 0
	for path, config := range paths {
		// Check if path exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			result.Details = append(result.Details,
				fmt.Sprintf("⊘ %s: skipped (does not exist)", path))
			continue
		}

		// Fix ownership
		if err := os.Chown(path, uid, gid); err != nil {
			result.Success = false
			result.Details = append(result.Details,
				fmt.Sprintf("✗ %s: failed to fix ownership: %v", path, err))
			continue
		}

		// Fix permissions
		if err := os.Chmod(path, config.perms); err != nil {
			result.Success = false
			result.Details = append(result.Details,
				fmt.Sprintf("✗ %s: failed to fix permissions: %v", path, err))
			continue
		}

		result.Details = append(result.Details,
			fmt.Sprintf("✓ %s: fixed ownership to consul:consul and permissions to %04o",
				path, config.perms))
		fixCount++
	}

	if fixCount > 0 {
		result.Message = fmt.Sprintf("Fixed permissions on %d path(s)", fixCount)
	} else {
		result.Message = "No permission fixes needed"
		result.ChangesMade = false
	}

	return result
}

// fixConfiguration applies configuration fixes from debug package
func fixConfiguration(rc *eos_io.RuntimeContext) FixResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Fixing Consul configuration")

	result := FixResult{
		Operation:   "Configuration Fix",
		Success:     true,
		ChangesMade: true,
		Details:     []string{},
	}

	// Run debug with AutoFix enabled
	debugConfig := &debug.Config{
		AutoFix:       true,
		KillProcesses: false,
		TestStart:     false,
		MinimalConfig: false,
		LogLines:      50,
	}

	if err := debug.RunDiagnostics(rc, debugConfig); err != nil {
		result.Success = false
		result.Message = "Configuration fixes failed"
		result.Details = append(result.Details, err.Error())
	} else {
		result.Message = "Configuration fixes applied"
		result.Details = append(result.Details, "Applied fixes from debug diagnostics")
	}

	return result
}

// restartConsulService restarts the Consul systemd service
func restartConsulService(rc *eos_io.RuntimeContext) FixResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Restarting Consul service")

	result := FixResult{
		Operation:   "Service Restart",
		Success:     true,
		ChangesMade: true,
		Details:     []string{},
	}

	// Restart the service
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "consul"},
		Capture: true,
	})

	if err != nil {
		result.Success = false
		result.Message = "Failed to restart Consul service"
		result.Details = append(result.Details, fmt.Sprintf("Error: %v", err))
		result.Details = append(result.Details, fmt.Sprintf("Output: %s", output))
		return result
	}

	result.Message = "Consul service restarted successfully"
	result.Details = append(result.Details, "Service restart completed")

	// Wait a moment and check status
	statusOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "consul"},
		Capture: true,
	})

	if err == nil {
		result.Details = append(result.Details,
			fmt.Sprintf("Service status: %s", statusOutput))
	}

	return result
}

// displayResults shows a formatted summary of all fix results
func displayResults(rc *eos_io.RuntimeContext, results []FixResult, dryRun bool) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("========================================")
	if dryRun {
		logger.Info("CONSUL FIX DRY RUN SUMMARY")
	} else {
		logger.Info("CONSUL FIX SUMMARY")
	}
	logger.Info("========================================")

	for _, result := range results {
		var status string
		if result.Success {
			if result.ChangesMade {
				status = "[FIXED]"
			} else {
				status = "[OK]"
			}
		} else {
			status = "[FAILED]"
		}

		logger.Info(fmt.Sprintf("%s %s", status, result.Operation))
		logger.Info(fmt.Sprintf("      %s", result.Message))

		if len(result.Details) > 0 {
			for _, detail := range result.Details {
				logger.Info("      " + detail)
			}
		}

		logger.Info("") // Blank line between operations
	}

	logger.Info("========================================")

	// Provide next steps
	if dryRun {
		logger.Info("NEXT STEPS:")
		logger.Info("  • Run without --dry-run to apply fixes: sudo eos fix consul")
	} else {
		logger.Info("VERIFICATION:")
		logger.Info("  • Check Consul status: sudo systemctl status consul")
		logger.Info("  • View cluster members: consul members")
		logger.Info("  • Check logs: sudo journalctl -u consul -f")
	}
}

// getExpectedPerms returns the expected permissions for a path
func getExpectedPerms(isDir bool) os.FileMode {
	if isDir {
		return 0750
	}
	return 0640
}
