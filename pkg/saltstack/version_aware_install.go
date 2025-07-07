package saltstack

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VersionAwareInstaller handles Salt installation with automatic version detection
type VersionAwareInstaller struct {
	installer       *Installer
	versionResolver *platform.VersionResolver
}

// NewVersionAwareInstaller creates a new version-aware Salt installer
func NewVersionAwareInstaller(rc *eos_io.RuntimeContext) *VersionAwareInstaller {
	return &VersionAwareInstaller{
		installer:       NewInstaller(),
		versionResolver: platform.NewVersionResolver(rc, "salt"),
	}
}

// Install performs Salt installation with automatic version detection (InstallationStrategy interface)
func (vai *VersionAwareInstaller) Install(rc *eos_io.RuntimeContext, version string, config *Config) error {
	// Update config with the provided version
	if version != "" {
		config.Version = version
	}
	return vai.InstallWithVersionDetection(rc, config)
}

// InstallWithVersionDetection performs Salt installation with automatic version detection
func (vai *VersionAwareInstaller) InstallWithVersionDetection(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Step 1: Resolve the target version
	targetVersion, err := vai.resolveTargetVersion(rc, config)
	if err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to resolve Salt version: %w", err))
	}

	logger.Info("Resolved Salt version for installation",
		zap.String("version", targetVersion),
		zap.String("source", "version_resolver"))

	// Step 2: Check if Salt is already installed
	isInstalled, installedVersion, err := vai.installer.CheckInstallation(rc)
	if err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to check existing installation: %w", err))
	}

	if isInstalled {
		logger.Info("Salt is already installed",
			zap.String("installed_version", installedVersion),
			zap.String("target_version", targetVersion))

		// Compare versions and decide whether to upgrade/reconfigure
		shouldProceed, err := vai.handleExistingInstallation(rc, installedVersion, targetVersion)
		if err != nil {
			return err
		}

		if !shouldProceed {
			logger.Info("Skipping Salt installation")
			return nil
		}
	}

	// Step 3: Detect Ubuntu version for repository configuration
	logger.Info("Detecting Ubuntu version for repository setup")
	ubuntuRelease, err := platform.DetectUbuntuRelease(rc)
	if err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to detect Ubuntu version: %w", err))
	}

	// Step 4: Configure repositories with version-aware URLs
	logger.Info("Setting up version-aware Salt repository")
	if err := vai.setupVersionAwareRepository(rc, ubuntuRelease, targetVersion); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to setup repository: %w", err))
	}

	// Step 5: Install Salt using the enhanced installer
	logger.Info("Installing Salt with version awareness")
	if err := vai.installer.installVersionAware(rc, config, targetVersion); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to install Salt: %w", err))
	}

	// Step 6: Configure Salt
	if err := vai.installer.Configure(rc, config); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to configure Salt: %w", err))
	}

	// Step 7: Verify installation unless skipped
	if !config.SkipTest {
		if err := vai.installer.Verify(rc); err != nil {
			return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("installation verification failed: %w", err))
		}
	}

	logger.Info("Version-aware Salt installation completed successfully",
		zap.String("version", targetVersion),
		zap.String("ubuntu_version", ubuntuRelease.Version),
		zap.String("ubuntu_codename", ubuntuRelease.Codename))

	return nil
}

// resolveTargetVersion determines which Salt version to install
func (vai *VersionAwareInstaller) resolveTargetVersion(rc *eos_io.RuntimeContext, config *Config) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// If a specific version is requested, use it
	if config.Version != "" && config.Version != "latest" {
		logger.Info("Using explicitly specified version",
			zap.String("version", config.Version))
		return config.Version, nil
	}

	// Otherwise, detect the latest version
	logger.Info("Detecting latest Salt version")
	version, err := vai.versionResolver.GetLatestVersion()
	if err != nil {
		logger.Warn("Failed to detect latest version, using fallback",
			zap.Error(err))
		return DefaultSaltVersion, nil
	}

	return version, nil
}

// handleExistingInstallation decides whether to proceed with installation when Salt exists
func (vai *VersionAwareInstaller) handleExistingInstallation(rc *eos_io.RuntimeContext, installedVersion, targetVersion string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Compare versions
	comparison := platform.CompareVersions(installedVersion, targetVersion)

	switch {
	case comparison > 0:
		// Installed version is newer
		logger.Info("Installed version is newer than target",
			zap.String("installed", installedVersion),
			zap.String("target", targetVersion))
		return vai.promptDowngrade(rc, installedVersion, targetVersion)

	case comparison == 0:
		// Same version - ask about reconfiguration
		logger.Info("Same version already installed",
			zap.String("version", installedVersion))
		return vai.installer.PromptReconfigure(rc)

	default:
		// Installed version is older - proceed with upgrade
		logger.Info("Upgrading Salt",
			zap.String("from", installedVersion),
			zap.String("to", targetVersion))
		return true, nil
	}
}

// promptDowngrade asks the user if they want to downgrade Salt
func (vai *VersionAwareInstaller) promptDowngrade(rc *eos_io.RuntimeContext, installedVersion, targetVersion string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Target version is older than installed version - this would be a downgrade")
	logger.Info("terminal prompt: Do you want to downgrade Salt?",
		zap.String("from", installedVersion),
		zap.String("to", targetVersion))

	// For now, default to not downgrading - this could be made interactive
	logger.Info("Automatic downgrade declined - keeping existing version")
	return false, nil
}

// setupVersionAwareRepository configures the Salt repository with version-aware URLs
func (vai *VersionAwareInstaller) setupVersionAwareRepository(rc *eos_io.RuntimeContext, ubuntuRelease *platform.UbuntuRelease, saltVersion string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create a custom repository configuration for the target version
	repoConfig := &SaltRepositoryConfig{
		UbuntuVersion:  ubuntuRelease.Version,
		UbuntuCodename: ubuntuRelease.Codename,
		SaltVersion:    saltVersion,
		Architecture:   "amd64",
	}

	logger.Debug("Repository configuration",
		zap.Any("config", repoConfig))

	// Set up the repository using the enhanced method
	return vai.setupEnhancedRepository(rc, repoConfig)
}

// SaltRepositoryConfig represents repository configuration for Salt
type SaltRepositoryConfig struct {
	UbuntuVersion  string
	UbuntuCodename string
	SaltVersion    string
	Architecture   string
}

// setupEnhancedRepository sets up the Salt repository with multiple fallback strategies
func (vai *VersionAwareInstaller) setupEnhancedRepository(rc *eos_io.RuntimeContext, config *SaltRepositoryConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Strategy 1: Try the specific version repository
	primaryRepoURL := platform.GetSaltRepoURL(config.UbuntuVersion, config.UbuntuCodename)
	primaryKeyURL := platform.GetSaltRepoKeyURL(config.UbuntuVersion)

	logger.Info("Attempting primary repository setup",
		zap.String("repo_url", primaryRepoURL),
		zap.String("key_url", primaryKeyURL))

	if err := vai.tryRepositorySetup(rc, primaryRepoURL, primaryKeyURL, "primary"); err == nil {
		return nil
	}

	// Strategy 2: Try fallback to latest/stable repository
	fallbackRepoURL := vai.getFallbackRepoURL(config)
	fallbackKeyURL := vai.getFallbackKeyURL(config)

	logger.Info("Primary repository failed, trying fallback",
		zap.String("repo_url", fallbackRepoURL),
		zap.String("key_url", fallbackKeyURL))

	if err := vai.tryRepositorySetup(rc, fallbackRepoURL, fallbackKeyURL, "fallback"); err == nil {
		return nil
	}

	// Strategy 3: Try legacy repository format
	legacyRepoURL := vai.getLegacyRepoURL(config)
	legacyKeyURL := vai.getLegacyKeyURL(config)

	logger.Info("Fallback repository failed, trying legacy format",
		zap.String("repo_url", legacyRepoURL),
		zap.String("key_url", legacyKeyURL))

	return vai.tryRepositorySetup(rc, legacyRepoURL, legacyKeyURL, "legacy")
}

// tryRepositorySetup attempts to set up a repository with the given URLs
func (vai *VersionAwareInstaller) tryRepositorySetup(rc *eos_io.RuntimeContext, repoURL, keyURL, strategy string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Attempting repository setup",
		zap.String("strategy", strategy),
		zap.String("repo_url", repoURL),
		zap.String("key_url", keyURL))

	// Create a temporary release struct for the existing method
	release := &platform.UbuntuRelease{
		Version:  "24.04", // This will be replaced by proper version-aware logic
		Codename: "noble",
	}

	// Update the installer to use the specific URLs
	return vai.installer.addRepositoryWithURLs(rc, release, repoURL, keyURL)
}

// Fallback URL generation methods
func (vai *VersionAwareInstaller) getFallbackRepoURL(config *SaltRepositoryConfig) string {
	// Try the latest stable repository
	return fmt.Sprintf("https://repo.saltproject.io/salt/py3/ubuntu/%s/%s/latest",
		config.UbuntuVersion, config.Architecture)
}

func (vai *VersionAwareInstaller) getFallbackKeyURL(config *SaltRepositoryConfig) string {
	// Use a stable key URL
	return fmt.Sprintf("https://repo.saltproject.io/salt/py3/ubuntu/%s/%s/SALTSTACK-GPG-KEY.pub",
		config.UbuntuVersion, config.Architecture)
}

func (vai *VersionAwareInstaller) getLegacyRepoURL(config *SaltRepositoryConfig) string {
	// Try alternative repository URL patterns
	return fmt.Sprintf("https://repo.saltproject.io/py3/ubuntu/%s/%s/latest",
		config.UbuntuVersion, config.Architecture)
}

func (vai *VersionAwareInstaller) getLegacyKeyURL(config *SaltRepositoryConfig) string {
	// Try alternative key URL patterns
	// Use the provided config for version-specific key URLs if available
	return fmt.Sprintf("https://repo.saltproject.io/salt/py3/ubuntu/%s/%s/SALTSTACK-GPG-KEY.pub",
		config.UbuntuVersion, config.Architecture)
}

// Name returns the name of this installation strategy
func (vai *VersionAwareInstaller) Name() string {
	return "Version-Aware Repository"
}

// Verify checks that Salt is working correctly after installation
func (vai *VersionAwareInstaller) Verify(rc *eos_io.RuntimeContext) error {
	return vai.installer.Verify(rc)
}
