package packer

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hashicorp"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NativeInstaller handles Packer installation using shared HashiCorp helpers
type NativeInstaller struct {
	*hashicorp.BaseInstaller
	rc     *eos_io.RuntimeContext
	config *PackerInstallConfig
}

// PackerInstallConfig contains Packer-specific installation configuration
type PackerInstallConfig struct {
	*hashicorp.InstallConfig
	PluginDirectory string
	CacheDirectory  string
}

// NewNativeInstaller creates a new Packer native installer
func NewNativeInstaller(rc *eos_io.RuntimeContext, config *PackerInstallConfig) *NativeInstaller {
	// Set defaults
	if config.InstallConfig == nil {
		config.InstallConfig = &hashicorp.InstallConfig{
			Product:       hashicorp.ProductPacker,
			Version:       "latest",
			InstallMethod: hashicorp.MethodBinary,
			BinaryPath:    "/usr/local/bin/packer",
			ConfigPath:    "/etc/packer",
			DataPath:      "/var/lib/packer",
			LogPath:       "/var/log/packer",
			ServiceName:   "", // Packer is a CLI tool, no service
			ServiceUser:   "", // No service user needed
			ServiceGroup:  "", // No service group needed
			Port:          0,  // No port needed
			TLSEnabled:    false,
		}
	}

	if config.PluginDirectory == "" {
		config.PluginDirectory = "/var/lib/packer/plugins"
	}
	if config.CacheDirectory == "" {
		config.CacheDirectory = "/var/cache/packer"
	}

	baseInstaller := hashicorp.NewBaseInstaller(rc, hashicorp.ProductPacker)

	return &NativeInstaller{
		BaseInstaller: baseInstaller,
		rc:            rc,
		config:        config,
	}
}

// Install performs the Packer installation
func (n *NativeInstaller) Install() error {
	logger := otelzap.Ctx(n.rc.Ctx)

	// Initialize progress reporter
	progress := hashicorp.NewProgressReporter(logger, "Packer Installation", 6)
	n.SetProgress(progress)

	// ASSESS - Check current status
	progress.Update("Checking current Packer status")
	status, err := n.CheckStatus(n.config.InstallConfig)
	if err != nil {
		logger.Warn("Could not determine current Packer status", zap.Error(err))
		status = &hashicorp.ProductStatus{}
	}

	// Check idempotency
	if status.Installed && !n.config.ForceReinstall {
		progress.Complete("Packer is already installed")
		logger.Info("Packer already installed", zap.String("version", status.Version))
		return nil
	}

	// Validate prerequisites
	progress.Update("Validating prerequisites")
	validator := hashicorp.NewValidator(logger)
	validator.RequireRoot()
	validator.RequireCommand("unzip")
	validator.CheckDiskSpace("/usr/local/bin", 150) // 150MB for Packer binary

	if validator.HasErrors() {
		progress.Failed("Prerequisites validation failed", validator.GetError())
		return validator.GetError()
	}

	// Clean install if requested
	if n.config.CleanInstall {
		progress.Update("Performing clean installation")
		if err := n.cleanInstallation(); err != nil {
			progress.Failed("Clean installation failed", err)
			return fmt.Errorf("failed to clean existing installation: %w", err)
		}
	}

	// INTERVENE - Install Packer
	progress.Update("Installing Packer binary")
	if n.config.InstallMethod == hashicorp.MethodRepository {
		if err := n.InstallViaRepository(n.config.InstallConfig); err != nil {
			progress.Failed("Repository installation failed", err)
			return fmt.Errorf("repository installation failed: %w", err)
		}
	} else {
		if err := n.InstallBinary(n.config.InstallConfig); err != nil {
			progress.Failed("Binary installation failed", err)
			return fmt.Errorf("binary installation failed: %w", err)
		}
	}

	// Setup plugin and cache directories
	progress.Update("Setting up plugin and cache directories")
	if err := n.setupDirectories(); err != nil {
		logger.Warn("Failed to setup directories", zap.Error(err))
	}

	// Setup environment
	progress.Update("Setting up environment")
	if err := n.setupEnvironment(); err != nil {
		logger.Warn("Failed to setup environment", zap.Error(err))
	}

	// EVALUATE - Verify installation
	progress.Update("Verifying installation")
	if err := n.verify(); err != nil {
		progress.Failed("Verification failed", err)
		return fmt.Errorf("verification failed: %w", err)
	}

	progress.Complete("Packer installation completed successfully")

	// Get installed version
	if output, err := n.GetRunner().RunOutput(n.config.BinaryPath, "version"); err == nil {
		logger.Info("Packer installation completed",
			zap.String("binary_path", n.config.BinaryPath),
			zap.String("version_output", output))
	}

	return nil
}

// cleanInstallation removes existing Packer installation
func (n *NativeInstaller) cleanInstallation() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Cleaning existing Packer installation")

	// Remove binary
	if err := n.GetRunner().RunQuiet("rm", "-f", n.config.BinaryPath); err != nil {
		logger.Warn("Failed to remove binary", zap.Error(err))
	}

	// Remove symlinks
	n.GetRunner().RunQuiet("rm", "-f", "/usr/bin/packer")

	// Clean plugin directory
	if n.config.PluginDirectory != "" {
		n.GetRunner().RunQuiet("rm", "-rf", n.config.PluginDirectory)
	}

	// Clean cache directory
	if n.config.CacheDirectory != "" {
		n.GetRunner().RunQuiet("rm", "-rf", n.config.CacheDirectory)
	}

	return nil
}

// setupDirectories creates plugin and cache directories
func (n *NativeInstaller) setupDirectories() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Setting up Packer directories")

	dirMgr := hashicorp.NewDirectoryManager(n.GetRunner())

	// Create plugin directory
	if err := dirMgr.CreateWithOwnership(
		n.config.PluginDirectory,
		"", // No specific user
		"", // No specific group
		0755,
	); err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}

	// Create cache directory
	if err := dirMgr.CreateWithOwnership(
		n.config.CacheDirectory,
		"", // No specific user
		"", // No specific group
		0755,
	); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Create config directory
	if err := dirMgr.CreateWithOwnership(
		n.config.ConfigPath,
		"", // No specific user
		"", // No specific group
		0755,
	); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	return nil
}

// setupEnvironment sets up environment variables for Packer
func (n *NativeInstaller) setupEnvironment() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Setting up Packer environment")

	// Create environment file for Packer
	envContent := fmt.Sprintf(`# Packer environment variables managed by Eos
export PACKER_PLUGIN_PATH="%s"
export PACKER_CACHE_DIR="%s"
export PACKER_LOG=0
export CHECKPOINT_DISABLE=1
`, n.config.PluginDirectory, n.config.CacheDirectory)

	// Write to profile.d for all users
	if err := n.GetFileManager().WriteWithOwnership(
		"/etc/profile.d/packer.sh",
		[]byte(envContent),
		0644,
		"root",
		"root",
	); err != nil {
		return fmt.Errorf("failed to write environment file: %w", err)
	}

	// Create a Packer config file
	configContent := `{
  "disable_checkpoint": true,
  "disable_checkpoint_signature": true
}
`

	configPath := fmt.Sprintf("%s/config.json", n.config.ConfigPath)
	if err := n.GetFileManager().WriteWithOwnership(
		configPath,
		[]byte(configContent),
		0644,
		"root",
		"root",
	); err != nil {
		logger.Warn("Failed to write config file", zap.Error(err))
	}

	return nil
}

// verify checks that Packer is installed correctly
func (n *NativeInstaller) verify() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Verifying Packer installation")

	// Check if binary exists and is executable
	if err := n.GetRunner().Run(n.config.BinaryPath, "version"); err != nil {
		return fmt.Errorf("Packer binary not working: %w", err)
	}

	// Test Packer init (will fail without a template, but that's ok)
	testDir := "/tmp/packer-test"
	dirMgr := hashicorp.NewDirectoryManager(n.GetRunner())
	if err := dirMgr.CreateWithOwnership(testDir, "", "", 0755); err != nil {
		return fmt.Errorf("failed to create test directory: %w", err)
	}
	defer dirMgr.RemoveIfExists(testDir)

	// Create a minimal test template
	testTemplate := `{
  "builders": [{
    "type": "null",
    "communicator": "none"
  }]
}
`
	testFile := fmt.Sprintf("%s/test.json", testDir)
	if err := n.GetFileManager().WriteWithOwnership(
		testFile,
		[]byte(testTemplate),
		0644,
		"", "",
	); err != nil {
		logger.Warn("Failed to create test template", zap.Error(err))
	} else {
		// Validate the test template
		if err := n.GetRunner().Run(n.config.BinaryPath, "validate", testFile); err != nil {
			logger.Warn("Packer validate test failed", zap.Error(err))
			// Non-fatal as Packer is still installed
		}
	}

	logger.Info("Packer verification successful")
	return nil
}
