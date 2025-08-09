package terraform

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hashicorp"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NativeInstaller handles Terraform installation using shared HashiCorp helpers
type NativeInstaller struct {
	*hashicorp.BaseInstaller
	rc     *eos_io.RuntimeContext
	config *TerraformInstallConfig
}

// TerraformInstallConfig contains Terraform-specific installation configuration
type TerraformInstallConfig struct {
	*hashicorp.InstallConfig
	PluginCacheDir string
	AutoApprove    bool
}

// NewNativeInstaller creates a new Terraform native installer
func NewNativeInstaller(rc *eos_io.RuntimeContext, config *TerraformInstallConfig) *NativeInstaller {
	// Set defaults
	if config.InstallConfig == nil {
		config.InstallConfig = &hashicorp.InstallConfig{
			Product:       hashicorp.ProductTerraform,
			Version:       "latest",
			InstallMethod: hashicorp.MethodBinary,
			BinaryPath:    "/usr/local/bin/terraform",
			ConfigPath:    "/etc/terraform",
			DataPath:      "/var/lib/terraform",
			LogPath:       "/var/log/terraform",
			ServiceName:   "", // Terraform is a CLI tool, no service
			ServiceUser:   "", // No service user needed
			ServiceGroup:  "", // No service group needed
			Port:          0,  // No port needed
			TLSEnabled:    false,
		}
	}
	
	if config.PluginCacheDir == "" {
		config.PluginCacheDir = "/var/lib/terraform/plugin-cache"
	}
	
	baseInstaller := hashicorp.NewBaseInstaller(rc, hashicorp.ProductTerraform)
	
	return &NativeInstaller{
		BaseInstaller: baseInstaller,
		rc:            rc,
		config:        config,
	}
}

// Install performs the Terraform installation
func (n *NativeInstaller) Install() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	
	// Initialize progress reporter
	progress := hashicorp.NewProgressReporter(logger, "Terraform Installation", 5)
	n.SetProgress(progress)
	
	// ASSESS - Check current status
	progress.Update("Checking current Terraform status")
	status, err := n.CheckStatus(n.config.InstallConfig)
	if err != nil {
		logger.Warn("Could not determine current Terraform status", zap.Error(err))
		status = &hashicorp.ProductStatus{}
	}
	
	// Check idempotency
	if status.Installed && !n.config.ForceReinstall {
		progress.Complete("Terraform is already installed")
		logger.Info("Terraform already installed", zap.String("version", status.Version))
		return nil
	}
	
	// Validate prerequisites
	progress.Update("Validating prerequisites")
	validator := hashicorp.NewValidator(logger)
	validator.RequireRoot()
	validator.RequireCommand("unzip")
	validator.CheckDiskSpace("/usr/local/bin", 200) // 200MB for Terraform binary
	
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
	
	// INTERVENE - Install Terraform
	progress.Update("Installing Terraform binary")
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
	
	// Setup plugin cache directory
	progress.Update("Setting up plugin cache directory")
	if err := n.setupPluginCache(); err != nil {
		logger.Warn("Failed to setup plugin cache", zap.Error(err))
	}
	
	// EVALUATE - Verify installation
	progress.Update("Verifying installation")
	if err := n.verify(); err != nil {
		progress.Failed("Verification failed", err)
		return fmt.Errorf("verification failed: %w", err)
	}
	
	progress.Complete("Terraform installation completed successfully")
	
	// Get installed version
	if output, err := n.GetRunner().RunOutput(n.config.BinaryPath, "version"); err == nil {
		logger.Info("Terraform installation completed",
			zap.String("binary_path", n.config.BinaryPath),
			zap.String("version_output", output))
	}
	
	return nil
}

// cleanInstallation removes existing Terraform installation
func (n *NativeInstaller) cleanInstallation() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Cleaning existing Terraform installation")
	
	// Remove binary
	if err := n.GetRunner().RunQuiet("rm", "-f", n.config.BinaryPath); err != nil {
		logger.Warn("Failed to remove binary", zap.Error(err))
	}
	
	// Remove symlinks
	n.GetRunner().RunQuiet("rm", "-f", "/usr/bin/terraform")
	
	// Clean plugin cache
	if n.config.PluginCacheDir != "" {
		n.GetRunner().RunQuiet("rm", "-rf", n.config.PluginCacheDir)
	}
	
	return nil
}

// setupPluginCache creates the plugin cache directory
func (n *NativeInstaller) setupPluginCache() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Setting up Terraform plugin cache directory",
		zap.String("path", n.config.PluginCacheDir))
	
	dirMgr := hashicorp.NewDirectoryManager(n.GetRunner())
	if err := dirMgr.CreateWithOwnership(
		n.config.PluginCacheDir,
		"", // No specific user
		"", // No specific group
		0755,
	); err != nil {
		return fmt.Errorf("failed to create plugin cache directory: %w", err)
	}
	
	// Create a global terraform CLI config
	cliConfig := fmt.Sprintf(`plugin_cache_dir = "%s"
disable_checkpoint = true
`, n.config.PluginCacheDir)
	
	cliConfigPath := "/etc/terraform/cli.tfrc"
	
	// Create config directory
	if err := dirMgr.CreateWithOwnership("/etc/terraform", "", "", 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	// Write CLI config
	if err := n.GetFileManager().WriteWithOwnership(
		cliConfigPath,
		[]byte(cliConfig),
		0644,
		"root",
		"root",
	); err != nil {
		return fmt.Errorf("failed to write CLI config: %w", err)
	}
	
	// Set environment variable for all users
	envContent := fmt.Sprintf(`export TF_CLI_CONFIG_FILE="%s"
export TF_PLUGIN_CACHE_DIR="%s"
`, cliConfigPath, n.config.PluginCacheDir)
	
	if err := n.GetFileManager().WriteWithOwnership(
		"/etc/profile.d/terraform.sh",
		[]byte(envContent),
		0644,
		"root",
		"root",
	); err != nil {
		logger.Warn("Failed to write environment file", zap.Error(err))
	}
	
	return nil
}

// verify checks that Terraform is installed correctly
func (n *NativeInstaller) verify() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Verifying Terraform installation")
	
	// Check if binary exists and is executable
	if err := n.GetRunner().Run(n.config.BinaryPath, "version"); err != nil {
		return fmt.Errorf("Terraform binary not working: %w", err)
	}
	
	// Initialize an empty directory to test Terraform
	testDir := "/tmp/terraform-test"
	dirMgr := hashicorp.NewDirectoryManager(n.GetRunner())
	if err := dirMgr.CreateWithOwnership(testDir, "", "", 0755); err != nil {
		return fmt.Errorf("failed to create test directory: %w", err)
	}
	defer dirMgr.RemoveIfExists(testDir)
	
	// Run terraform init in test directory
	if err := n.GetRunner().Run("bash", "-c", 
		fmt.Sprintf("cd %s && %s init -backend=false", testDir, n.config.BinaryPath)); err != nil {
		logger.Warn("Terraform init test failed", zap.Error(err))
		// Non-fatal as Terraform is still installed
	}
	
	logger.Info("Terraform verification successful")
	return nil
}