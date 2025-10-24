// pkg/nomad/install.go

package nomad

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

// InstallConfig contains all configuration for Nomad installation
type InstallConfig struct {
	// Installation method
	Version       string // Version to install
	UseRepository bool   // Use APT repository vs direct binary download
	BinaryPath    string // Path for binary installation

	// Nomad configuration
	ServerEnabled     bool
	ClientEnabled     bool
	Datacenter        string
	Region            string
	BootstrapExpect   int
	ConsulIntegration bool
	VaultIntegration  bool
	DockerEnabled     bool
	BindAddr          string
	AdvertiseAddr     string
	LogLevel          string

	// Installation behavior
	ForceReinstall bool
	CleanInstall   bool
	DryRun         bool
}

// NomadInstaller handles Nomad installation
type NomadInstaller struct {
	rc      *eos_io.RuntimeContext
	config  *InstallConfig
	logger  otelzap.LoggerWithCtx
	runner  *CommandRunner
	systemd *SystemdService
}

// NewNomadInstaller creates a new simplified Nomad installer
func NewNomadInstaller(rc *eos_io.RuntimeContext, config *InstallConfig) *NomadInstaller {
	// Set defaults
	if config.Version == "" {
		config.Version = "latest"
	}
	if config.Datacenter == "" {
		config.Datacenter = "dc1"
	}
	if config.Region == "" {
		config.Region = "global"
	}
	if config.LogLevel == "" {
		config.LogLevel = "INFO"
	}
	if config.BindAddr == "" {
		config.BindAddr = "0.0.0.0"
	}
	if config.BootstrapExpect == 0 && config.ServerEnabled {
		config.BootstrapExpect = 1
	}
	if !config.ServerEnabled && !config.ClientEnabled {
		config.ServerEnabled = true
		config.ClientEnabled = true
	}

	runner := NewCommandRunner(rc)
	return &NomadInstaller{
		rc:      rc,
		config:  config,
		logger:  otelzap.Ctx(rc.Ctx),
		runner:  runner,
		systemd: NewSystemdService(runner, "nomad"),
	}
}

// Install performs simplified Nomad installation
func (ni *NomadInstaller) Install() error {
	ni.logger.Info("Installing Nomad",
		zap.String("version", ni.config.Version),
		zap.Bool("server", ni.config.ServerEnabled),
		zap.Bool("client", ni.config.ClientEnabled))

	// Phase 1: ASSESS
	if !ni.config.ForceReinstall {
		if _, err := ni.runner.RunOutput("nomad", "version"); err == nil {
			if ni.systemd.IsActive() {
				ni.logger.Info("Nomad is already installed and running")
				ni.logger.Info("terminal prompt:  Nomad is already installed and running")
				ni.logger.Info(fmt.Sprintf("terminal prompt: Web UI available at: http://<server-ip>:%d", shared.PortNomad))
				return nil
			}
		}
	}

	// Check prerequisites
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	// Phase 2: INTERVENE - Install binary
	ni.logger.Info("Downloading and installing Nomad")

	arch := runtime.GOARCH
	downloadURL := fmt.Sprintf("https://releases.hashicorp.com/nomad/%s/nomad_%s_linux_%s.zip",
		ni.config.Version, ni.config.Version, arch)

	tmpDir := "/tmp/nomad-install"
	_ = os.MkdirAll(tmpDir, 0755)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if err := ni.runner.Run("wget", "-O", tmpDir+"/nomad.zip", downloadURL); err != nil {
		if ni.config.Version == "latest" {
			downloadURL = fmt.Sprintf("https://releases.hashicorp.com/nomad/1.6.2/nomad_1.6.2_linux_%s.zip", arch)
			if err := ni.runner.Run("wget", "-O", tmpDir+"/nomad.zip", downloadURL); err != nil {
				return fmt.Errorf("failed to download Nomad: %w", err)
			}
		} else {
			return fmt.Errorf("failed to download Nomad: %w", err)
		}
	}

	if err := ni.runner.Run("unzip", "-o", tmpDir+"/nomad.zip", "-d", tmpDir); err != nil {
		return fmt.Errorf("failed to extract Nomad: %w", err)
	}

	if err := ni.runner.Run("install", "-m", "755", tmpDir+"/nomad", "/usr/local/bin/nomad"); err != nil {
		return fmt.Errorf("failed to install Nomad binary: %w", err)
	}

	// Create user and directories using centralized user manager
	userMgr := NewUserHelper(ni.runner)
	if err := userMgr.CreateSystemUser("nomad", "/var/lib/nomad"); err != nil {
		return fmt.Errorf("failed to create nomad user: %w", err)
	}
	_ = os.MkdirAll("/etc/nomad.d", 0755)
	_ = os.MkdirAll("/opt/nomad/data", 0755)
	_ = os.MkdirAll("/var/log/nomad", 0755)
	_ = ni.runner.Run("chown", "-R", "nomad:nomad", "/opt/nomad")
	_ = ni.runner.Run("chown", "-R", "nomad:nomad", "/var/log/nomad")

	// Write configuration
	ni.writeConfiguration()

	// Setup systemd service
	ni.setupSystemdService()

	// Phase 3: EVALUATE
	if output, err := ni.runner.RunOutput("nomad", "version"); err != nil {
		return fmt.Errorf("Nomad installation verification failed: %w", err)
	} else {
		ni.logger.Info("Nomad installed successfully", zap.String("version", output))
	}

	ni.logger.Info("terminal prompt:  Nomad installation completed!")
	ni.logger.Info(fmt.Sprintf("terminal prompt: Web UI available at: http://<server-ip>:%d", shared.PortNomad))
	ni.logger.Info("terminal prompt: Check status with: nomad node status")

	return nil
}

func (ni *NomadInstaller) writeConfiguration() {
	var serverConfig string
	if ni.config.ServerEnabled {
		serverConfig = fmt.Sprintf(`
server {
  enabled = true
  bootstrap_expect = %d
}`, ni.config.BootstrapExpect)
	}

	var clientConfig string
	if ni.config.ClientEnabled {
		clientConfig = `
client {
  enabled = true
}`
	}

	config := fmt.Sprintf(`datacenter = "%s"
region = "%s"
data_dir = "/opt/nomad/data"
log_level = "%s"
bind_addr = "%s"

ports {
  http = %d
  rpc = 4647
  serf = 4648
}
%s
%s`, ni.config.Datacenter, ni.config.Region, ni.config.LogLevel,
		ni.config.BindAddr, shared.PortNomad, serverConfig, clientConfig)

	// SECURITY P0 #2: Check critical file write errors
	if err := os.WriteFile("/etc/nomad.d/nomad.hcl", []byte(config), 0640); err != nil {
		panic(fmt.Sprintf("FATAL: Failed to write Nomad config: %v", err))
	}
	_ = ni.runner.Run("chown", "nomad:nomad", "/etc/nomad.d/nomad.hcl")
}

func (ni *NomadInstaller) setupSystemdService() {
	serviceContent := `[Unit]
Description=HashiCorp Nomad
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=nomad
Group=nomad
ExecStart=/usr/local/bin/nomad agent -config=/etc/nomad.d/
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
TasksMax=infinity

[Install]
WantedBy=multi-user.target`

	// SECURITY P0 #2: Check critical file write errors
	// SECURITY P2 #6: Use 0640 instead of 0644 for service file (contains paths)
	if err := os.WriteFile("/etc/systemd/system/nomad.service", []byte(serviceContent), 0640); err != nil {
		panic(fmt.Sprintf("FATAL: Failed to write Nomad service file: %v", err))
	}
	_ = ni.runner.Run("systemctl", "daemon-reload")
	_ = ni.runner.Run("systemctl", "enable", "nomad")
	_ = ni.runner.Run("systemctl", "start", "nomad")
}
