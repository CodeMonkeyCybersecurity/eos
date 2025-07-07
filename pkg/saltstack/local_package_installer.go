package saltstack

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// LocalPackageInstaller handles Salt installation using local package manager (apt)
// This is the most reliable fallback that doesn't require external repositories
type LocalPackageInstaller struct {
	configurer *Configurer
	verifier   *Verifier
}

// NewLocalPackageInstaller creates a new local package installer
func NewLocalPackageInstaller() *LocalPackageInstaller {
	return &LocalPackageInstaller{
		configurer: NewConfigurer(),
		verifier:   NewVerifier(),
	}
}

// Name returns the name of this installation strategy
func (lpi *LocalPackageInstaller) Name() string {
	return "Local Package Manager"
}

// Install performs Salt installation using the system's package manager
func (lpi *LocalPackageInstaller) Install(rc *eos_io.RuntimeContext, version string, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Salt installation using local package manager",
		zap.String("version", version),
		zap.Bool("master_mode", config.MasterMode))

	// Step 1: Detect the system and package manager
	if err := lpi.validateSystemSupport(rc); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("system not supported for local package installation: %w", err))
	}

	// Step 2: Update package cache
	logger.Info("Updating package cache")
	if err := lpi.updatePackageCache(rc); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to update package cache: %w", err))
	}

	// Step 3: Check if Salt is available in local repositories
	availableVersion, err := lpi.checkSaltAvailability(rc)
	if err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("Salt not available in local repositories: %w", err))
	}

	logger.Info("Salt available in local repositories",
		zap.String("available_version", availableVersion))

	// Step 4: Install Salt packages
	if err := lpi.installSaltPackages(rc, config); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to install Salt packages: %w", err))
	}

	// Step 5: Configure Salt for masterless operation
	if !config.MasterMode {
		if err := lpi.configureMasterlessMode(rc, config); err != nil {
			return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to configure masterless mode: %w", err))
		}
	}

	// Step 6: Create initial state tree structure
	if err := lpi.createStateTreeStructure(rc); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to create state tree: %w", err))
	}

	logger.Info("Salt local package installation completed successfully",
		zap.String("installed_version", availableVersion))
	return nil
}

// validateSystemSupport checks if the system supports local package installation
func (lpi *LocalPackageInstaller) validateSystemSupport(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if we're on a supported Ubuntu system
	release, err := platform.DetectUbuntuRelease(rc)
	if err != nil {
		return fmt.Errorf("not running on Ubuntu: %w", err)
	}

	logger.Debug("Detected Ubuntu system",
		zap.String("version", release.Version),
		zap.String("codename", release.Codename))

	// Check if apt is available
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"apt-get"},
		Timeout: 5 * time.Second,
	})

	if err != nil {
		return fmt.Errorf("apt package manager not available")
	}

	return nil
}

// updatePackageCache updates the local package cache
func (lpi *LocalPackageInstaller) updatePackageCache(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "apt-get",
		Args:    []string{"update"},
		Timeout: 120 * time.Second,
	})

	if err != nil {
		logger.Error("Package cache update failed", zap.String("output", output))
		return fmt.Errorf("apt-get update failed: %w", err)
	}

	logger.Debug("Package cache updated successfully")
	return nil
}

// checkSaltAvailability checks if Salt is available in local repositories
func (lpi *LocalPackageInstaller) checkSaltAvailability(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if salt-minion package is available
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "apt-cache",
		Args:    []string{"show", "salt-minion"},
		Timeout: 30 * time.Second,
	})

	if err != nil {
		logger.Debug("salt-minion package not found in cache", zap.Error(err))
		return "", fmt.Errorf("salt-minion package not available in local repositories")
	}

	// Extract version from apt-cache output
	version := lpi.extractVersionFromAptOutput(output)
	if version == "" {
		logger.Warn("Could not determine Salt version from apt cache")
		version = "unknown"
	}

	logger.Debug("Salt package found in local repositories",
		zap.String("version", version))

	return version, nil
}

// extractVersionFromAptOutput extracts version information from apt-cache output
func (lpi *LocalPackageInstaller) extractVersionFromAptOutput(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Version:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// installSaltPackages installs the required Salt packages
func (lpi *LocalPackageInstaller) installSaltPackages(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	packages := []string{"salt-minion", "salt-common"}

	logger.Info("Installing Salt packages",
		zap.Strings("packages", packages))

	args := []string{"install", "-y", "--no-install-recommends"}
	args = append(args, packages...)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "apt-get",
		Args:    args,
		Timeout: 300 * time.Second,
	})

	if err != nil {
		logger.Error("Package installation failed", zap.String("output", output))
		return fmt.Errorf("failed to install Salt packages: %w", err)
	}

	// Stop the salt-minion service (we'll configure it first)
	logger.Info("Stopping salt-minion service for configuration")
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"stop", "salt-minion"},
		Timeout: 30 * time.Second,
	})

	if err != nil {
		logger.Warn("Failed to stop salt-minion service", zap.Error(err))
		// This is not fatal, continue
	}

	logger.Info("Salt packages installed successfully")
	return nil
}

// configureMasterlessMode configures Salt for masterless operation
func (lpi *LocalPackageInstaller) configureMasterlessMode(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Configuring Salt for masterless operation")

	// Use the existing configurer
	return lpi.configurer.Configure(rc, config)
}

// createStateTreeStructure creates the basic Salt state tree structure
func (lpi *LocalPackageInstaller) createStateTreeStructure(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating Salt state tree structure")

	// Use the bootstrap installer's method (it's well-tested)
	bi := NewBootstrapInstaller()
	return bi.createStateTreeStructure(rc)
}

// Verify checks that Salt is working correctly after installation
func (lpi *LocalPackageInstaller) Verify(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying Salt local package installation")

	// Use the existing verifier
	return lpi.verifier.Verify(rc)
}