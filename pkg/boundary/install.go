// pkg/boundary/install.go

package boundary

import (
	"fmt"
	"os"
	"runtime"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallConfig contains configuration for Boundary installation
type InstallConfig struct {
	Version           string
	UseRepository     bool
	ControllerEnabled bool
	WorkerEnabled     bool
	DatabaseURL       string
	ClusterAddr       string
	PublicAddr        string
	AuthMethodID      string
	RecoveryKmsType   string
	KmsKeyID          string
	DevMode           bool
	ForceReinstall    bool
	CleanInstall      bool
}

// BoundaryInstaller handles Boundary installation
type BoundaryInstaller struct {
	rc      *eos_io.RuntimeContext
	config  *InstallConfig
	logger  otelzap.LoggerWithCtx
	runner  *CommandRunner
	systemd *SystemdService
}

// NewBoundaryInstaller creates a new Boundary installer
func NewBoundaryInstaller(rc *eos_io.RuntimeContext, config *InstallConfig) *BoundaryInstaller {
	if config.Version == "" {
		config.Version = "latest"
	}
	if !config.ControllerEnabled && !config.WorkerEnabled {
		if config.DevMode {
			config.ControllerEnabled = true
		} else {
			config.ControllerEnabled = true
			config.WorkerEnabled = true
		}
	}
	if config.ClusterAddr == "" {
		config.ClusterAddr = fmt.Sprintf("%s:%d", shared.GetInternalHostname(), shared.PortBoundary+1)
	}
	if config.PublicAddr == "" {
		config.PublicAddr = fmt.Sprintf("%s:%d", shared.GetInternalHostname(), shared.PortBoundary)
	}
	if config.RecoveryKmsType == "" {
		config.RecoveryKmsType = "aead"
	}

	runner := NewCommandRunner(rc)
	return &BoundaryInstaller{
		rc:      rc,
		config:  config,
		logger:  otelzap.Ctx(rc.Ctx),
		runner:  runner,
		systemd: NewSystemdService(runner, "boundary"),
	}
}

// Install performs Boundary installation
func (bi *BoundaryInstaller) Install() error {
	bi.logger.Info("Installing Boundary",
		zap.String("version", bi.config.Version),
		zap.Bool("controller", bi.config.ControllerEnabled),
		zap.Bool("worker", bi.config.WorkerEnabled))

	// Phase 1: ASSESS
	if !bi.config.ForceReinstall {
		if _, err := bi.runner.RunOutput("boundary", "version"); err == nil {
			if bi.systemd.IsActive() {
				bi.logger.Info("Boundary is already installed and running")
				bi.logger.Info("terminal prompt:  Boundary is already installed and running")
				bi.logger.Info(fmt.Sprintf("terminal prompt: Web UI available at: http://<server-ip>:%d", shared.PortBoundary))
				return nil
			}
		}
	}

	// Check prerequisites
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	// Phase 2: INTERVENE - Install
	bi.logger.Info("Downloading and installing Boundary")

	arch := runtime.GOARCH
	downloadURL := fmt.Sprintf("https://releases.hashicorp.com/boundary/%s/boundary_%s_linux_%s.zip",
		bi.config.Version, bi.config.Version, arch)

	tmpDir := "/tmp/boundary-install"
	_ = os.MkdirAll(tmpDir, 0755)
	defer os.RemoveAll(tmpDir)

	// Download and extract
	if err := bi.runner.Run("wget", "-O", tmpDir+"/boundary.zip", downloadURL); err != nil {
		if bi.config.Version == "latest" {
			// Simplified - use a known good version
			downloadURL = fmt.Sprintf("https://releases.hashicorp.com/boundary/0.13.0/boundary_0.13.0_linux_%s.zip", arch)
			if err := bi.runner.Run("wget", "-O", tmpDir+"/boundary.zip", downloadURL); err != nil {
				return fmt.Errorf("failed to download Boundary: %w", err)
			}
		} else {
			return fmt.Errorf("failed to download Boundary: %w", err)
		}
	}

	if err := bi.runner.Run("unzip", "-o", tmpDir+"/boundary.zip", "-d", tmpDir); err != nil {
		return fmt.Errorf("failed to extract Boundary: %w", err)
	}

	if err := bi.runner.Run("install", "-m", "755", tmpDir+"/boundary", "/usr/local/bin/boundary"); err != nil {
		return fmt.Errorf("failed to install Boundary binary: %w", err)
	}

	// Create user and directories using centralized user manager
	userMgr := NewUserHelper(bi.runner)
	if err := userMgr.CreateSystemUser("boundary", "/var/lib/boundary"); err != nil {
		return fmt.Errorf("failed to create boundary user: %w", err)
	}
	_ = os.MkdirAll("/etc/boundary.d", 0755)
	_ = os.MkdirAll("/var/lib/boundary", 0700)
	_ = os.MkdirAll("/var/log/boundary", 0755)
	bi.runner.Run("chown", "-R", "boundary:boundary", "/var/lib/boundary")
	bi.runner.Run("chown", "-R", "boundary:boundary", "/var/log/boundary")

	// Write basic configuration
	if bi.config.DevMode {
		config := fmt.Sprintf(`disable_mlock = true

controller {
  name = "dev-controller"
  database {
    url = "postgresql://boundary:boundary@localhost/boundary?sslmode=disable"
  }
}

listener "tcp" {
  address = "%s:9200"
  purpose = "api"
}

listener "tcp" {
  address = "%s:9201"
  purpose = "cluster"
}

kms "aead" {
  purpose = "root"
  aead_type = "aes-gcm"
  key = "sP1fnF5Xz85RrXyELHFeZg9Ad2qt4Z4bgNHVGtD6ung="
  key_id = "global_root"
}

kms "aead" {
  purpose = "worker-auth"
  aead_type = "aes-gcm"
  key = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GcvFo="
  key_id = "global_worker-auth"
}

kms "aead" {
  purpose = "recovery"
  aead_type = "aes-gcm"
  key = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GcvFo="
  key_id = "global_recovery"
}`, shared.GetInternalHostname(), shared.GetInternalHostname())
		_ = os.WriteFile("/etc/boundary.d/boundary.hcl", []byte(config), 0640)
		bi.runner.Run("chown", "boundary:boundary", "/etc/boundary.d/boundary.hcl")
	}

	// Setup systemd service
	serviceContent := `[Unit]
Description=HashiCorp Boundary
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=boundary
Group=boundary
ExecStart=/usr/local/bin/boundary server -config=/etc/boundary.d/
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target`

	_ = os.WriteFile("/etc/systemd/system/boundary.service", []byte(serviceContent), 0644)
	bi.runner.Run("systemctl", "daemon-reload")

	if !bi.config.DevMode {
		// In production mode, don't start automatically
		bi.logger.Info("Boundary installed. Configure /etc/boundary.d/boundary.hcl before starting")
	} else {
		// In dev mode, can try to start
		bi.runner.Run("systemctl", "enable", "boundary")
		if err := bi.runner.Run("systemctl", "start", "boundary"); err != nil {
			bi.logger.Warn("Failed to start Boundary service", zap.Error(err))
		}
	}

	// Phase 3: EVALUATE
	if output, err := bi.runner.RunOutput("boundary", "version"); err != nil {
		return fmt.Errorf("Boundary installation verification failed: %w", err)
	} else {
		bi.logger.Info("Boundary installed successfully", zap.String("version", output))
	}

	bi.logger.Info("terminal prompt:  Boundary installation completed!")
	bi.logger.Info(fmt.Sprintf("terminal prompt: Web UI will be available at: http://<server-ip>:%d", shared.PortBoundary))
	bi.logger.Info("terminal prompt: Configure /etc/boundary.d/boundary.hcl then start with: systemctl start boundary")

	return nil
}
