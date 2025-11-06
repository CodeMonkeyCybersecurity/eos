//go:build linux

// pkg/kvm/package_upgrade.go
// Package upgrade operations for VMs via guest-exec

package kvm

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PackageUpgradeConfig configures package upgrade behavior
type PackageUpgradeConfig struct {
	// Upgrade behavior
	UpdateOnly   bool // Only update package lists, don't upgrade
	SecurityOnly bool // Only security updates (Ubuntu only)
	AutoRemove   bool // Run apt autoremove after upgrade
	AutoClean    bool // Run apt autoclean after upgrade

	// Safety
	DryRun    bool // Show what would be upgraded
	AssumeYes bool // Non-interactive mode (default: true)

	// Timeout
	UpdateTimeout  time.Duration // Timeout for apt update (default: 5min)
	UpgradeTimeout time.Duration // Timeout for apt upgrade (default: 30min)

	// Retry
	RetryOnLock    bool          // Retry if dpkg/apt is locked
	LockRetries    int           // Max retries for lock (default: 3)
	LockRetryDelay time.Duration // Delay between retries (default: 30s)
}

// DefaultPackageUpgradeConfig returns sensible defaults
func DefaultPackageUpgradeConfig() *PackageUpgradeConfig {
	return &PackageUpgradeConfig{
		AssumeYes:      true,
		AutoRemove:     true,
		AutoClean:      true,
		UpdateTimeout:  5 * time.Minute,
		UpgradeTimeout: 30 * time.Minute,
		RetryOnLock:    true,
		LockRetries:    3,
		LockRetryDelay: 30 * time.Second,
	}
}

// PackageUpgradeResult contains upgrade operation results
type PackageUpgradeResult struct {
	Success          bool          `json:"success"`
	PackagesUpdated  int           `json:"packages_updated"`
	PackagesUpgraded int           `json:"packages_upgraded"`
	PackagesRemoved  int           `json:"packages_removed"`
	UpdateOutput     string        `json:"update_output"`
	UpgradeOutput    string        `json:"upgrade_output"`
	ErrorMessage     string        `json:"error_message,omitempty"`
	Duration         time.Duration `json:"duration"`
	RebootRequired   bool          `json:"reboot_required"`
}

// UpgradeVMPackages performs package upgrade inside a VM
// Follows Assess → Intervene → Evaluate pattern
func UpgradeVMPackages(rc *eos_io.RuntimeContext, vmName string, cfg *PackageUpgradeConfig) (*PackageUpgradeResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	if cfg == nil {
		cfg = DefaultPackageUpgradeConfig()
	}

	logger.Info("Starting package upgrade",
		zap.String("vm", vmName),
		zap.Bool("dry_run", cfg.DryRun),
		zap.Bool("security_only", cfg.SecurityOnly))

	result := &PackageUpgradeResult{}

	// ASSESS: Check prerequisites and current state
	if err := assessPackageUpgrade(rc, vmName); err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Assessment failed: %v", err)
		return result, err
	}

	// INTERVENE: Perform upgrade operations
	if err := intervenePackageUpgrade(rc, vmName, cfg, result); err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Upgrade failed: %v", err)
		return result, err
	}

	// EVALUATE: Verify upgrade completed successfully
	if err := evaluatePackageUpgrade(rc, vmName, result); err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Verification failed: %v", err)
		return result, err
	}

	result.Success = true
	result.Duration = time.Since(startTime)

	logger.Info("Package upgrade completed",
		zap.String("vm", vmName),
		zap.Int("packages_upgraded", result.PackagesUpgraded),
		zap.Bool("reboot_required", result.RebootRequired),
		zap.Duration("duration", result.Duration))

	return result, nil
}

// assessPackageUpgrade verifies VM is ready for package operations
func assessPackageUpgrade(rc *eos_io.RuntimeContext, vmName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Assessing package upgrade readiness",
		zap.String("vm", vmName))

	// Check dpkg/apt locks
	script := `
# Check if dpkg/apt is locked
if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
   fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
   fuser /var/cache/apt/archives/lock >/dev/null 2>&1; then
    echo "LOCKED"
    exit 1
else
    echo "UNLOCKED"
    exit 0
fi
`

	execCfg := DefaultGuestExecConfig()
	execCfg.Timeout = 30 * time.Second
	execResult, err := GuestExecScript(rc, vmName, script, execCfg.Timeout)
	if err != nil {
		return fmt.Errorf("failed to check package locks: %w", err)
	}

	if execResult.ExitCode != 0 {
		return fmt.Errorf("dpkg/apt is locked by another process - wait for it to complete or run 'eos update kvm %s' with --retry-on-lock", vmName)
	}

	logger.Debug("Package system is available",
		zap.String("vm", vmName))

	return nil
}

// intervenePackageUpgrade performs the actual upgrade operations
func intervenePackageUpgrade(rc *eos_io.RuntimeContext, vmName string, cfg *PackageUpgradeConfig, result *PackageUpgradeResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Step 1: apt update
	logger.Info("Running apt update",
		zap.String("vm", vmName))

	updateScript := buildUpdateScript(cfg)
	updateResult, err := retryOnLock(rc, vmName, updateScript, cfg.UpdateTimeout, cfg)
	if err != nil {
		return fmt.Errorf("apt update failed: %w", err)
	}

	result.UpdateOutput = updateResult.Stdout
	if updateResult.ExitCode != 0 {
		return fmt.Errorf("apt update failed with exit code %d:\n%s\n%s",
			updateResult.ExitCode, updateResult.Stdout, updateResult.Stderr)
	}

	// Parse update output for package counts
	result.PackagesUpdated = parsePackageCount(updateResult.Stdout, "packages can be upgraded")

	logger.Info("apt update completed",
		zap.String("vm", vmName),
		zap.Int("packages_available", result.PackagesUpdated))

	// Step 2: apt upgrade (unless --update-only)
	if !cfg.UpdateOnly {
		logger.Info("Running apt upgrade",
			zap.String("vm", vmName),
			zap.Bool("dry_run", cfg.DryRun))

		upgradeScript := buildUpgradeScript(cfg)
		upgradeResult, err := retryOnLock(rc, vmName, upgradeScript, cfg.UpgradeTimeout, cfg)
		if err != nil {
			return fmt.Errorf("apt upgrade failed: %w", err)
		}

		result.UpgradeOutput = upgradeResult.Stdout
		if upgradeResult.ExitCode != 0 {
			return fmt.Errorf("apt upgrade failed with exit code %d:\n%s\n%s",
				upgradeResult.ExitCode, upgradeResult.Stdout, upgradeResult.Stderr)
		}

		// Parse upgrade output
		result.PackagesUpgraded = parsePackageCount(upgradeResult.Stdout, "upgraded")
		result.PackagesRemoved = parsePackageCount(upgradeResult.Stdout, "newly installed") // apt output varies

		logger.Info("apt upgrade completed",
			zap.String("vm", vmName),
			zap.Int("packages_upgraded", result.PackagesUpgraded))
	}

	// Step 3: apt autoremove (if enabled)
	if cfg.AutoRemove && !cfg.DryRun {
		logger.Info("Running apt autoremove",
			zap.String("vm", vmName))

		autoremoveScript := "export DEBIAN_FRONTEND=noninteractive && sudo apt-get autoremove -y"
		_, err := GuestExecScript(rc, vmName, autoremoveScript, 5*time.Minute)
		if err != nil {
			logger.Warn("apt autoremove failed", zap.Error(err))
			// Don't fail the whole operation
		}
	}

	// Step 4: apt autoclean (if enabled)
	if cfg.AutoClean && !cfg.DryRun {
		logger.Info("Running apt autoclean",
			zap.String("vm", vmName))

		autocleanScript := "export DEBIAN_FRONTEND=noninteractive && sudo apt-get autoclean -y"
		_, err := GuestExecScript(rc, vmName, autocleanScript, 2*time.Minute)
		if err != nil {
			logger.Warn("apt autoclean failed", zap.Error(err))
			// Don't fail the whole operation
		}
	}

	return nil
}

// evaluatePackageUpgrade verifies upgrade was successful
func evaluatePackageUpgrade(rc *eos_io.RuntimeContext, vmName string, result *PackageUpgradeResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Verifying package upgrade",
		zap.String("vm", vmName))

	// Check if reboot is required
	script := `
if [ -f /var/run/reboot-required ]; then
    echo "REBOOT_REQUIRED"
    cat /var/run/reboot-required.pkgs 2>/dev/null || echo "unknown packages"
    exit 0
else
    echo "NO_REBOOT_REQUIRED"
    exit 0
fi
`

	execResult, err := GuestExecScript(rc, vmName, script, 10*time.Second)
	if err != nil {
		logger.Warn("Failed to check reboot requirement", zap.Error(err))
		// Don't fail - just can't determine reboot status
		return nil
	}

	if strings.Contains(execResult.Stdout, "REBOOT_REQUIRED") {
		result.RebootRequired = true
		logger.Info("Reboot required after upgrade",
			zap.String("vm", vmName))
	}

	return nil
}

// retryOnLock retries a script if dpkg/apt locks are encountered
func retryOnLock(rc *eos_io.RuntimeContext, vmName string, script string, timeout time.Duration, cfg *PackageUpgradeConfig) (*GuestExecResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	maxRetries := 1
	if cfg.RetryOnLock {
		maxRetries = cfg.LockRetries
	}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		result, err := GuestExecScript(rc, vmName, script, timeout)

		// Check for lock-related errors
		if err == nil && result.ExitCode == 0 {
			return result, nil
		}

		// Check if error is lock-related
		isLocked := false
		if result != nil {
			combinedOutput := result.Stdout + result.Stderr
			isLocked = strings.Contains(combinedOutput, "dpkg was interrupted") ||
				strings.Contains(combinedOutput, "Unable to lock") ||
				strings.Contains(combinedOutput, "Could not get lock") ||
				strings.Contains(combinedOutput, "dpkg frontend is locked")
		}

		if !isLocked || !cfg.RetryOnLock {
			// Not a lock error or retries disabled - fail immediately
			if err != nil {
				return nil, err
			}
			return result, nil
		}

		// Lock detected and retries enabled
		lastErr = fmt.Errorf("dpkg/apt locked (attempt %d/%d)", attempt, maxRetries)
		logger.Warn("Package system locked, will retry",
			zap.Int("attempt", attempt),
			zap.Int("max_retries", maxRetries),
			zap.Duration("retry_delay", cfg.LockRetryDelay))

		if attempt < maxRetries {
			time.Sleep(cfg.LockRetryDelay)
		}
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// buildUpdateScript creates the apt update command
func buildUpdateScript(cfg *PackageUpgradeConfig) string {
	return "export DEBIAN_FRONTEND=noninteractive && sudo apt-get update"
}

// buildUpgradeScript creates the apt upgrade command
func buildUpgradeScript(cfg *PackageUpgradeConfig) string {
	script := "export DEBIAN_FRONTEND=noninteractive && sudo apt-get"

	if cfg.DryRun {
		script += " --dry-run"
	}

	if cfg.SecurityOnly {
		script += " upgrade -y --only-upgrade --security"
	} else {
		script += " upgrade -y"
	}

	return script
}

// parsePackageCount extracts package counts from apt output
func parsePackageCount(output, pattern string) int {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, pattern) {
			// Try to extract number from patterns like:
			// "5 packages can be upgraded"
			// "10 upgraded, 2 newly installed"
			fields := strings.Fields(line)
			for i, field := range fields {
				if strings.Contains(strings.ToLower(field), strings.ToLower(strings.Fields(pattern)[0])) && i > 0 {
					// Number is typically before the pattern word
					var count int
					if _, err := fmt.Sscanf(fields[i-1], "%d", &count); err == nil {
						return count
					}
				}
			}
		}
	}
	return 0
}
