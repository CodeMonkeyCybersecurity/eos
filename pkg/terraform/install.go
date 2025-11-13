// pkg/terraform/install.go

package terraform

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"runtime"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallConfig contains configuration for Terraform installation
type InstallConfig struct {
	Version        string
	UseRepository  bool
	PluginCacheDir string
	AutoApprove    bool
	ForceReinstall bool
	CleanInstall   bool
}

// TerraformInstaller handles Terraform installation
type TerraformInstaller struct {
	rc     *eos_io.RuntimeContext
	config *InstallConfig
	logger otelzap.LoggerWithCtx
	runner *CommandRunner
}

// NewTerraformInstaller creates a new Terraform installer
func NewTerraformInstaller(rc *eos_io.RuntimeContext, config *InstallConfig) *TerraformInstaller {
	if config.Version == "" {
		config.Version = "latest"
	}
	if config.PluginCacheDir == "" {
		config.PluginCacheDir = "/var/lib/terraform/plugin-cache"
	}

	return &TerraformInstaller{
		rc:     rc,
		config: config,
		logger: otelzap.Ctx(rc.Ctx),
		runner: NewCommandRunner(rc),
	}
}

// Install performs Terraform installation
func (ti *TerraformInstaller) Install() error {
	ti.logger.Info("Installing Terraform",
		zap.String("version", ti.config.Version))

	// Phase 1: ASSESS
	if !ti.config.ForceReinstall {
		if _, err := ti.runner.RunOutput("terraform", "version"); err == nil {
			ti.logger.Info("Terraform is already installed")
			ti.logger.Info("terminal prompt:  Terraform is already installed")
			ti.logger.Info("terminal prompt: To check version: terraform version")
			return nil
		}
	}

	// Check prerequisites
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	// Phase 2: INTERVENE - Install
	ti.logger.Info("Downloading and installing Terraform")

	// For simplicity, download and install binary
	arch := runtime.GOARCH
	downloadURL := fmt.Sprintf("https://releases.hashicorp.com/terraform/%s/terraform_%s_linux_%s.zip",
		ti.config.Version, ti.config.Version, arch)

	tmpDir := "/tmp/terraform-install"
	_ = os.MkdirAll(tmpDir, shared.ServiceDirPerm)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Download and extract
	if err := ti.runner.Run("wget", "-O", tmpDir+"/terraform.zip", downloadURL); err != nil {
		// If version is "latest", try without version
		if ti.config.Version == "latest" {
			// Simplified - just use a known good version
			downloadURL = fmt.Sprintf("https://releases.hashicorp.com/terraform/1.5.7/terraform_1.5.7_linux_%s.zip", arch)
			if err := ti.runner.Run("wget", "-O", tmpDir+"/terraform.zip", downloadURL); err != nil {
				return fmt.Errorf("failed to download Terraform: %w", err)
			}
		} else {
			return fmt.Errorf("failed to download Terraform: %w", err)
		}
	}

	if err := ti.runner.Run("unzip", "-o", tmpDir+"/terraform.zip", "-d", tmpDir); err != nil {
		return fmt.Errorf("failed to extract Terraform: %w", err)
	}

	if err := ti.runner.Run("install", "-m", "755", tmpDir+"/terraform", "/usr/local/bin/terraform"); err != nil {
		return fmt.Errorf("failed to install Terraform binary: %w", err)
	}

	// Setup plugin cache dir
	_ = os.MkdirAll(ti.config.PluginCacheDir, shared.ServiceDirPerm)

	// Phase 3: EVALUATE
	if output, err := ti.runner.RunOutput("terraform", "version"); err != nil {
		return fmt.Errorf("Terraform installation verification failed: %w", err)
	} else {
		ti.logger.Info("Terraform installed successfully", zap.String("version", output))
	}

	ti.logger.Info("terminal prompt:  Terraform installation completed!")
	ti.logger.Info("terminal prompt: To initialize a project: terraform init")

	return nil
}
