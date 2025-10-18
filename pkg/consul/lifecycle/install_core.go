// pkg/consul/install_core.go
// Core installation orchestration (moved from install.go)

package lifecycle

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/systemd"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Install performs the complete Consul installation
func (ci *ConsulInstaller) Install() error {
	ci.logger.Info("Starting Consul installation",
		zap.String("version", ci.config.Version),
		zap.String("datacenter", ci.config.Datacenter),
		zap.Bool("use_repository", ci.config.UseRepository))

	// Track installation progress for rollback
	installComplete := false
	binaryInstalled := false
	configCreated := false
	serviceCreated := false

	// CRITICAL: Rollback partial installation on failure
	defer func() {
		if !installComplete {
			ci.logger.Warn("Installation failed, attempting rollback of partial changes")
			ci.rollbackPartialInstall(binaryInstalled, configCreated, serviceCreated)
		}
	}()

	// Phase 1: ASSESS - Check if already installed
	ci.progress.Update("[16%] Checking if Consul is already installed and running...")
	shouldInstall, err := ci.assess()
	if err != nil {
		return fmt.Errorf("assessment failed: %w", err)
	}

	// If Consul is already properly installed and running, we're done
	if !shouldInstall {
		ci.logger.Info("Consul is already installed and running properly")
		ci.progress.Complete("Consul is already installed and running")
		installComplete = true // Don't rollback if already installed
		return nil
	}

	// Phase 2: Prerequisites
	ci.progress.Update("[33%] Checking system requirements (memory, disk, ports)...")
	if err := ci.validatePrerequisites(); err != nil {
		return fmt.Errorf("prerequisite validation failed: %w", err)
	}

	// Phase 3: INTERVENE - Install
	if ci.config.UseRepository {
		ci.progress.Update("[50%] Downloading and installing Consul from HashiCorp repository...")
	} else {
		ci.progress.Update("[50%] Downloading and installing Consul binary...")
	}
	if err := ci.installBinary(); err != nil {
		return fmt.Errorf("binary installation failed: %w", err)
	}
	binaryInstalled = true

	// Phase 4: Configure
	ci.progress.Update("[66%] Generating and validating Consul configuration files...")
	if err := ci.configure(); err != nil {
		return fmt.Errorf("configuration failed: %w", err)
	}
	configCreated = true

	// Phase 5: Setup Service
	ci.progress.Update("[83%] Creating systemd service and starting Consul...")
	if err := ci.setupService(); err != nil {
		return fmt.Errorf("service setup failed: %w", err)
	}
	serviceCreated = true

	// Phase 6: EVALUATE - Verify
	ci.progress.Update("[100%] Waiting for Consul API to become ready...")
	if err := ci.verify(); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	ci.progress.Complete("Consul installation completed successfully")
	installComplete = true
	return nil
}

// assess checks the current state of Consul installation
// Returns true if installation should proceed, false if already installed
func (ci *ConsulInstaller) assess() (bool, error) {
	ci.logger.Info("Assessing current Consul installation")

	// Create context with timeout for assessment operations
	ctx, cancel := context.WithTimeout(ci.rc.Ctx, 30*time.Second)
	defer cancel()

	// First, check if Consul binary exists
	if _, err := os.Stat(ci.config.BinaryPath); err == nil {
		// Binary exists, check version with context
		if output, err := ci.runner.RunOutput(ci.config.BinaryPath, "version"); err == nil {
			ci.logger.Info("Consul binary found", zap.String("output", output))
		}
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	// Check if Consul service exists
	if status, err := ci.systemd.GetStatus(); err == nil {
		ci.logger.Info("Consul service found", zap.String("status", status))

		if !ci.config.ForceReinstall {
			// Check if it's running
			if ci.systemd.IsActive() {
				// Verify it's actually working
				if ci.isConsulReady() {
					ci.logger.Info("Consul is already installed and running properly")

					// Print service information
					ci.logger.Info("terminal prompt: ✓ Consul is already installed and running")
					ci.logger.Info(fmt.Sprintf("terminal prompt: Web UI available at: http://<server-ip>:%d", shared.PortConsul))
					ci.logger.Info("terminal prompt: ")
					ci.logger.Info("terminal prompt: To check status: consul members")
					ci.logger.Info("terminal prompt: To view logs: journalctl -u consul -f")

					return false, nil // Don't install, already running
				}
				ci.logger.Warn("Consul service is active but not responding properly")
				// Fall through to attempt repair/reinstall
			} else {
				ci.logger.Info("Consul is installed but not running")
				ci.logger.Info("Service not running, will proceed with installation to fix any issues")
			}
		} else {
			ci.logger.Info("Force reinstall requested, proceeding with installation")
			if ci.config.CleanInstall {
				if err := ci.cleanExistingInstallation(); err != nil {
					return false, fmt.Errorf("failed to clean existing installation: %w", err)
				}
			}
		}
	}

	return true, nil // Proceed with installation
}

// configure sets up Consul configuration
func (ci *ConsulInstaller) configure() error {
	ci.logger.Info("Configuring Consul")

	// Create context for configuration operations
	ctx, cancel := context.WithTimeout(ci.rc.Ctx, 30*time.Second)
	defer cancel()

	// Create consul user and group
	if err := ci.user.CreateSystemUser("consul", "/var/lib/consul"); err != nil {
		return fmt.Errorf("failed to create consul user: %w", err)
	}

	// Define required directories
	type DirectoryConfig struct {
		Path  string
		Mode  os.FileMode
		Owner string
	}

	directories := []DirectoryConfig{
		{Path: "/etc/consul.d", Mode: 0755, Owner: "consul"},
		{Path: "/var/lib/consul", Mode: 0755, Owner: "consul"},
		{Path: "/var/log/consul", Mode: 0755, Owner: "consul"},
		{Path: "/opt/consul", Mode: 0755, Owner: "consul"},
	}

	criticalDirs := map[string]bool{
		"/var/lib/consul": true,
		"/var/log/consul": true,
	}

	for _, dir := range directories {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := ci.createDirectory(dir.Path, dir.Mode); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir.Path, err)
		}

		// Set ownership
		if err := ci.runner.Run("chown", "-R", dir.Owner+":"+dir.Owner, dir.Path); err != nil {
			if criticalDirs[dir.Path] {
				return fmt.Errorf("failed to set ownership on critical directory %s: %w", dir.Path, err)
			}
			ci.logger.Warn("Failed to set directory ownership", zap.String("path", dir.Path), zap.Error(err))
		} else if criticalDirs[dir.Path] {
			if err := ci.verifyDirectoryOwnership(dir.Path, dir.Owner); err != nil {
				return fmt.Errorf("ownership verification failed: %w", err)
			}
		}
	}

	// Create logrotate configuration
	if err := ci.createLogrotateConfig(); err != nil {
		ci.logger.Warn("Failed to create logrotate config", zap.Error(err))
	}

	// Check for crash looping service
	if status, err := ci.systemd.GetStatus(); err == nil {
		if strings.Contains(strings.ToLower(status), "activating") &&
			strings.Contains(strings.ToLower(status), "exit-code") {
			ci.logger.Warn("Service is in crash loop, stopping before reconfiguration")
			if err := ci.systemd.Stop(); err != nil {
				return fmt.Errorf("failed to stop crash looping service: %w", err)
			}
			// Wait for stop
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				if !ci.systemd.IsActive() {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
		}
	}

	// Generate configuration
	consulConfig := &config.ConsulConfig{
		DatacenterName:     ci.config.Datacenter,
		EnableDebugLogging: ci.config.LogLevel == "DEBUG",
		VaultAvailable:     ci.config.VaultIntegration,
		BootstrapExpect:    ci.config.BootstrapExpect,
	}

	if err := ci.CheckDiskSpaceWithContext(context.Background(), "/etc", 10); err != nil {
		return fmt.Errorf("insufficient disk space for config write: %w", err)
	}

	if err := config.Generate(ci.rc, consulConfig); err != nil {
		return fmt.Errorf("failed to generate configuration: %w", err)
	}

	// Validate configuration
	ci.logger.Info("Validating Consul configuration")
	output, err := ci.runner.RunOutput(ci.config.BinaryPath, "validate", "/etc/consul.d")
	if err != nil {
		return fmt.Errorf("configuration validation failed: %w (output: %s)", err, output)
	}

	ci.logger.Info("Consul configuration validated successfully")
	return nil
}

// setupService configures and starts the Consul systemd service
func (ci *ConsulInstaller) setupService() error {
	ci.logger.Info("Setting up Consul systemd service")

	// Use systemd package to create service file
	if err := systemd.CreateService(ci.rc); err != nil {
		return fmt.Errorf("failed to create systemd service: %w", err)
	}

	// Reload systemd daemon
	if err := ci.systemd.ReloadDaemon(); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w", err)
	}

	// Enable service
	if err := ci.systemd.Enable(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	// Start service
	if err := ci.systemd.Start(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	ci.logger.Info("Consul service started successfully")
	return nil
}

// rollbackPartialInstall cleans up a failed installation
func (ci *ConsulInstaller) rollbackPartialInstall(binaryInstalled, configCreated, serviceCreated bool) {
	ci.logger.Info("Rolling back partial installation",
		zap.Bool("binary_installed", binaryInstalled),
		zap.Bool("config_created", configCreated),
		zap.Bool("service_created", serviceCreated))

	// Stop service first
	if serviceCreated {
		ci.logger.Info("Stopping service created during failed installation")
		if err := ci.systemd.Stop(); err != nil {
			ci.logger.Warn("Failed to stop service during rollback", zap.Error(err))
		}

		// Wait for service to stop
		deadline := time.Now().Add(5 * time.Second)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		for time.Now().Before(deadline) {
			if !ci.systemd.IsActive() {
				break
			}
			<-ticker.C
		}

		// Remove systemd service file
		servicePath := "/etc/systemd/system/consul.service"
		if err := os.Remove(servicePath); err != nil {
			ci.logger.Warn("Failed to remove service file", zap.Error(err))
		}

		// Reload systemd
		if _, err := ci.runner.RunOutput("systemctl", "daemon-reload"); err != nil {
			ci.logger.Warn("Failed to reload systemd", zap.Error(err))
		}
	}

	// Remove config
	if configCreated {
		ci.logger.Info("Removing configuration created during failed installation")
		for _, path := range []string{"/etc/consul.d/consul.hcl", "/etc/consul.d"} {
			if err := os.RemoveAll(path); err != nil {
				ci.logger.Warn("Failed to remove config", zap.String("path", path), zap.Error(err))
			}
		}
	}

	// Remove binary if installed via direct download
	if binaryInstalled && !ci.config.UseRepository {
		ci.logger.Info("Removing binary installed during failed installation")
		if err := os.Remove(ci.config.BinaryPath); err != nil {
			ci.logger.Warn("Failed to remove binary", zap.Error(err))
		}
	}

	ci.logger.Info("Rollback completed")
}

// RunCreateConsul is the main entry point for the consul create command
func RunCreateConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	// Determine server/client mode by reading flags from command
	consulServer, _ := cmd.Flags().GetBool("server")
	consulClient, _ := cmd.Flags().GetBool("client")
	consulClean, _ := cmd.Flags().GetBool("clean")

	serverMode := consulServer
	if consulServer && consulClient {
		return eos_err.NewUserError("cannot specify both --server and --client flags")
	}
	if !consulServer && !consulClient {
		serverMode = true
		logger.Info("Defaulting to server mode")
	}

	// Warn about destructive operations
	if consulClean {
		logger.Warn("--clean flag specified: This will DELETE all existing Consul data")
		logger.Info("terminal prompt: Type 'yes' to confirm or Ctrl+C to cancel: ")

		var confirmation string
		fmt.Scanln(&confirmation)
		if strings.ToLower(strings.TrimSpace(confirmation)) != "yes" {
			return eos_err.NewUserError("clean install cancelled by user")
		}
	}

	// Read all flags from command
	consulDatacenter, _ := cmd.Flags().GetString("datacenter")
	consulVersion, _ := cmd.Flags().GetString("version")
	consulNoVault, _ := cmd.Flags().GetBool("no-vault-integration")
	consulDebug, _ := cmd.Flags().GetBool("debug")
	consulBindAddr, _ := cmd.Flags().GetString("bind-addr")
	consulForce, _ := cmd.Flags().GetBool("force")
	consulBinary, _ := cmd.Flags().GetBool("binary")

	logger.Info("Starting native Consul installation",
		zap.String("datacenter", consulDatacenter),
		zap.Bool("server_mode", serverMode),
		zap.String("version", consulVersion))

	// Create installation config
	installConfig := &InstallConfig{
		Version:          consulVersion,
		Datacenter:       consulDatacenter,
		ServerMode:       serverMode,
		BootstrapExpect:  1,
		UIEnabled:        true,
		ConnectEnabled:   true,
		VaultIntegration: !consulNoVault,
		LogLevel:         GetConsulLogLevel(consulDebug),
		BindAddr:         consulBindAddr,
		ClientAddr:       "0.0.0.0",
		ForceReinstall:   consulForce,
		CleanInstall:     consulClean,
		UseRepository:    !consulBinary,
	}

	// Create installer
	installer, err := NewConsulInstaller(rc, installConfig)
	if err != nil {
		return fmt.Errorf("failed to create consul installer: %w", err)
	}

	// Run installation
	if err := installer.Install(); err != nil {
		return fmt.Errorf("consul installation failed: %w", err)
	}

	// Success message
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ✓ Consul installation completed successfully!")
	logger.Info("terminal prompt: ")
	logger.Info(fmt.Sprintf("terminal prompt: Web UI: http://<server-ip>:%d/ui", shared.PortConsul))
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Quick Start:")
	logger.Info("terminal prompt:   consul members              # View cluster members")
	logger.Info("terminal prompt:   journalctl -u consul -f     # View live logs")
	logger.Info(fmt.Sprintf("terminal prompt:   curl http://localhost:%d/v1/agent/self  # Test API", shared.PortConsul))

	return nil
}

func GetConsulLogLevel(debug bool) string {
	if debug {
		return "DEBUG"
	}
	return "INFO"
}
