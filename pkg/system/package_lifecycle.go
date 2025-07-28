package system

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CleanupAPTPackages performs system-wide APT package cleanup
// This includes running autoremove and autoclean to remove orphaned packages
// and clean the package cache. This is a generic operation that benefits
// the entire system after component removals.
func CleanupAPTPackages(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Performing system-wide APT package cleanup")

	cli := eos_cli.New(rc)
	
	// Run apt autoremove to remove packages that were automatically
	// installed to satisfy dependencies but are no longer needed
	logger.Info("Running apt-get autoremove")
	if output, err := cli.ExecString("apt-get", "autoremove", "-y"); err != nil {
		logger.Warn("Failed to run apt autoremove", zap.Error(err))
		// Don't fail the entire operation if cleanup fails
	} else {
		logger.Info("APT autoremove completed", zap.String("output", output))
	}

	// Run apt autoclean to remove retrieved package files that can no
	// longer be downloaded and are largely useless
	logger.Info("Running apt-get autoclean")
	if output, err := cli.ExecString("apt-get", "autoclean"); err != nil {
		logger.Warn("Failed to run apt autoclean", zap.Error(err))
		// Don't fail the entire operation if cleanup fails
	} else {
		logger.Info("APT autoclean completed", zap.String("output", output))
	}

	logger.Info("System-wide APT cleanup completed")
	return nil
}

// UpdateAPTCache updates the APT package cache
// This should be called after removing APT sources to ensure
// the package cache reflects the current repository state
func UpdateAPTCache(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Updating APT package cache")

	cli := eos_cli.New(rc)
	
	if output, err := cli.ExecString("apt-get", "update"); err != nil {
		logger.Error("Failed to update APT cache", 
			zap.Error(err),
			zap.String("output", output))
		return err
	}

	logger.Info("APT cache updated successfully")
	return nil
}

// CleanupSystemPackages performs comprehensive system package cleanup
// This combines APT cleanup with other package management tasks
func CleanupSystemPackages(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting comprehensive system package cleanup")

	// First update the cache to ensure we have current package info
	if err := UpdateAPTCache(rc); err != nil {
		logger.Warn("Failed to update APT cache, continuing with cleanup", zap.Error(err))
	}

	// Perform APT cleanup
	if err := CleanupAPTPackages(rc); err != nil {
		return err
	}

	// Future: Add support for other package managers (snap, flatpak, etc.)
	
	logger.Info("System package cleanup completed")
	return nil
}