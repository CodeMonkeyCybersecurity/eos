package saltstack

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Installer handles SaltStack installation operations
type Installer struct {
	configurer *Configurer
	verifier   *Verifier
}

// NewInstaller creates a new SaltStack installer instance
func NewInstaller() *Installer {
	return &Installer{
		configurer: NewConfigurer(),
		verifier:   NewVerifier(),
	}
}

// CheckInstallation checks if Salt is already installed
func (i *Installer) CheckInstallation(rc *eos_io.RuntimeContext) (bool, string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Assessment: Check if salt-call command exists
	logger.Debug("Checking for salt-call command")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"salt-call"},
		Timeout: 10 * time.Second,
	})
	
	if err != nil {
		logger.Debug("salt-call not found in PATH")
		return false, "", nil
	}
	
	logger.Debug("salt-call found", zap.String("path", strings.TrimSpace(output)))
	
	// Get version information
	versionOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--version"},
		Timeout: 10 * time.Second,
	})
	
	if err != nil {
		logger.Warn("Failed to get Salt version", zap.Error(err))
		return true, "unknown", nil
	}
	
	// Parse version from output (format: "salt-call 3006.3")
	version := "unknown"
	if parts := strings.Fields(versionOutput); len(parts) >= 2 {
		version = parts[1]
	}
	
	return true, version, nil
}

// PromptReconfigure asks the user if they want to reconfigure existing Salt installation
func (i *Installer) PromptReconfigure(rc *eos_io.RuntimeContext) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Salt is already installed. Do you want to reconfigure it? (y/n)")
	
	response := interaction.PromptYesNo(rc.Ctx, "Reconfigure existing Salt installation?", false)
	
	return response, nil
}

// Install performs the Salt installation
func (i *Installer) Install(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Step 1: Detect Ubuntu version
	logger.Info("Detecting Ubuntu version")
	release, err := i.detectUbuntuRelease(rc)
	if err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to detect Ubuntu release: %w", err))
	}
	
	logger.Info("Detected Ubuntu release", 
		zap.String("version", release.Version),
		zap.String("codename", release.Codename),
	)
	
	// Step 2: Add Salt repository
	logger.Info("Adding SaltStack repository")
	if err := i.addRepository(rc, release); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to add Salt repository: %w", err))
	}
	
	// Step 3: Update package list
	logger.Info("Updating package list")
	if err := i.updatePackages(rc); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to update packages: %w", err))
	}
	
	// Step 4: Install salt-minion package
	logger.Info("Installing salt-minion package")
	if err := i.installPackage(rc, config); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to install salt-minion: %w", err))
	}
	
	logger.Info("Salt installation completed successfully")
	return nil
}

// Configure sets up Salt configuration
func (i *Installer) Configure(rc *eos_io.RuntimeContext, config *Config) error {
	return i.configurer.Configure(rc, config)
}

// Verify checks that Salt is working correctly
func (i *Installer) Verify(rc *eos_io.RuntimeContext) error {
	return i.verifier.Verify(rc)
}

// detectUbuntuRelease detects the current Ubuntu version and codename using platform utility
func (i *Installer) detectUbuntuRelease(rc *eos_io.RuntimeContext) (*platform.UbuntuRelease, error) {
	return platform.DetectUbuntuRelease(rc)
}

// addRepository adds the Salt repository to apt sources
func (i *Installer) addRepository(rc *eos_io.RuntimeContext, release *platform.UbuntuRelease) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Step 1: Download and add the repository key
	logger.Info("Adding SaltStack repository key")
	
	// Create keyring directory if it doesn't exist
	keyringDir := "/usr/share/keyrings"
	if err := os.MkdirAll(keyringDir, 0755); err != nil {
		return fmt.Errorf("failed to create keyring directory: %w", err)
	}
	
	// Download the key
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args: []string{
			"-fsSL",
			SaltRepoKey,
			"-o",
			"/usr/share/keyrings/salt-archive-keyring.gpg",
		},
		Timeout: 30 * time.Second,
	})
	
	if err != nil {
		return fmt.Errorf("failed to download repository key: %w", err)
	}
	
	// Step 2: Create apt sources list entry
	logger.Info("Creating apt sources list entry")
	
	repoLine := fmt.Sprintf(
		"deb [signed-by=/usr/share/keyrings/salt-archive-keyring.gpg arch=amd64] %s",
		platform.GetSaltRepoURL(release.Version, release.Codename),
	)
	
	// Write to sources list
	repoListPath := GetRepoListPath()
	if err := os.WriteFile(repoListPath, []byte(repoLine+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write sources list: %w", err)
	}
	
	logger.Debug("Repository added", zap.String("path", repoListPath))
	return nil
}

// updatePackages updates the apt package list
func (i *Installer) updatePackages(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "apt-get",
		Args:    []string{"update"},
		Timeout: 120 * time.Second,
	})
	
	if err != nil {
		logger.Error("Package update failed", zap.String("output", output))
		return fmt.Errorf("apt-get update failed: %w", err)
	}
	
	logger.Debug("Package list updated successfully")
	return nil
}

// installPackage installs the salt-minion package
func (i *Installer) installPackage(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Determine which package to install
	packageName := "salt-minion"
	if config.MasterMode {
		// In master mode, we still install minion but will configure it differently
		logger.Info("Installing salt-minion for master-minion mode")
	}
	
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "apt-get",
		Args: []string{
			"install",
			"-y",
			"--no-install-recommends",
			packageName,
		},
		Timeout: 300 * time.Second,
	})
	
	if err != nil {
		logger.Error("Package installation failed", zap.String("output", output))
		return fmt.Errorf("failed to install %s: %w", packageName, err)
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
	
	logger.Info("Salt package installed successfully", zap.String("package", packageName))
	return nil
}

// installVersionAware installs Salt with version awareness
func (i *Installer) installVersionAware(rc *eos_io.RuntimeContext, config *Config, targetVersion string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Installing Salt with version awareness",
		zap.String("target_version", targetVersion),
		zap.Bool("master_mode", config.MasterMode))

	// For now, use the standard installation process
	// In the future, this could be enhanced to handle version-specific installation methods
	return i.installPackage(rc, config)
}

// addRepositoryWithURLs adds the Salt repository using specific URLs
func (i *Installer) addRepositoryWithURLs(rc *eos_io.RuntimeContext, release *platform.UbuntuRelease, repoURL, keyURL string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Step 1: Download and add the repository key using the specific URL
	logger.Info("Adding SaltStack repository key", zap.String("key_url", keyURL))

	// Create keyring directory if it doesn't exist
	keyringDir := "/usr/share/keyrings"
	if err := os.MkdirAll(keyringDir, 0755); err != nil {
		return fmt.Errorf("failed to create keyring directory: %w", err)
	}

	// Download the key using the specific URL
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args: []string{
			"-fsSL",
			keyURL,
			"-o",
			"/usr/share/keyrings/salt-archive-keyring.gpg",
		},
		Timeout: 30 * time.Second,
	})

	if err != nil {
		return fmt.Errorf("failed to download repository key from %s: %w", keyURL, err)
	}

	// Step 2: Create apt sources list entry using the specific repository URL
	logger.Info("Creating apt sources list entry", zap.String("repo_url", repoURL))

	repoLine := fmt.Sprintf(
		"deb [signed-by=/usr/share/keyrings/salt-archive-keyring.gpg arch=amd64] %s %s main",
		repoURL,
		release.Codename,
	)

	// Write to sources list
	repoListPath := GetRepoListPath()
	if err := os.WriteFile(repoListPath, []byte(repoLine+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write sources list: %w", err)
	}

	logger.Debug("Repository added",
		zap.String("path", repoListPath),
		zap.String("repo_url", repoURL),
		zap.String("key_url", keyURL))

	return nil
}