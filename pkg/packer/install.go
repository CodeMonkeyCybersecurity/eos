// pkg/packer/install.go

package packer

import (
	"fmt"
	"os"
	"runtime"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallConfig contains configuration for Packer installation
type InstallConfig struct {
	Version         string
	UseRepository   bool
	PluginDirectory string
	CacheDirectory  string
	ForceReinstall  bool
	CleanInstall    bool
}

// PackerInstaller handles Packer installation
type PackerInstaller struct {
	rc     *eos_io.RuntimeContext
	config *InstallConfig
	logger otelzap.LoggerWithCtx
	runner *CommandRunner
}

// NewPackerInstaller creates a new Packer installer
func NewPackerInstaller(rc *eos_io.RuntimeContext, config *InstallConfig) *PackerInstaller {
	if config.Version == "" {
		config.Version = "latest"
	}
	if config.PluginDirectory == "" {
		config.PluginDirectory = "/var/lib/packer/plugins"
	}
	if config.CacheDirectory == "" {
		config.CacheDirectory = "/var/cache/packer"
	}

	return &PackerInstaller{
		rc:     rc,
		config: config,
		logger: otelzap.Ctx(rc.Ctx),
		runner: NewCommandRunner(rc),
	}
}

// Install performs Packer installation
func (pi *PackerInstaller) Install() error {
	pi.logger.Info("Installing Packer",
		zap.String("version", pi.config.Version))

	// Phase 1: ASSESS
	if !pi.config.ForceReinstall {
		if _, err := pi.runner.RunOutput("packer", "version"); err == nil {
			pi.logger.Info("Packer is already installed")
			pi.logger.Info("terminal prompt:  Packer is already installed")
			pi.logger.Info("terminal prompt: To check version: packer version")
			return nil
		}
	}

	// Check prerequisites
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	// Phase 2: INTERVENE - Install
	pi.logger.Info("Downloading and installing Packer")

	arch := runtime.GOARCH
	downloadURL := fmt.Sprintf("https://releases.hashicorp.com/packer/%s/packer_%s_linux_%s.zip",
		pi.config.Version, pi.config.Version, arch)

	tmpDir := "/tmp/packer-install"
	_ = os.MkdirAll(tmpDir, 0755)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Download and extract
	if err := pi.runner.Run("wget", "-O", tmpDir+"/packer.zip", downloadURL); err != nil {
		// If version is "latest", try without version
		if pi.config.Version == "latest" {
			// Simplified - just use a known good version
			downloadURL = fmt.Sprintf("https://releases.hashicorp.com/packer/1.9.4/packer_1.9.4_linux_%s.zip", arch)
			if err := pi.runner.Run("wget", "-O", tmpDir+"/packer.zip", downloadURL); err != nil {
				return fmt.Errorf("failed to download Packer: %w", err)
			}
		} else {
			return fmt.Errorf("failed to download Packer: %w", err)
		}
	}

	if err := pi.runner.Run("unzip", "-o", tmpDir+"/packer.zip", "-d", tmpDir); err != nil {
		return fmt.Errorf("failed to extract Packer: %w", err)
	}

	if err := pi.runner.Run("install", "-m", "755", tmpDir+"/packer", "/usr/local/bin/packer"); err != nil {
		return fmt.Errorf("failed to install Packer binary: %w", err)
	}

	// Setup directories
	_ = os.MkdirAll(pi.config.PluginDirectory, 0755)
	_ = os.MkdirAll(pi.config.CacheDirectory, 0755)

	// Phase 3: EVALUATE
	if output, err := pi.runner.RunOutput("packer", "version"); err != nil {
		return fmt.Errorf("Packer installation verification failed: %w", err)
	} else {
		pi.logger.Info("Packer installed successfully", zap.String("version", output))
	}

	pi.logger.Info("terminal prompt:  Packer installation completed!")
	pi.logger.Info("terminal prompt: To validate a template: packer validate template.pkr.hcl")

	return nil
}
