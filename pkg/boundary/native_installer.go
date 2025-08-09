package boundary

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hashicorp"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NativeInstaller handles Boundary installation using shared HashiCorp helpers
type NativeInstaller struct {
	*hashicorp.BaseInstaller
	rc     *eos_io.RuntimeContext
	config *BoundaryInstallConfig
}

// BoundaryInstallConfig contains Boundary-specific installation configuration
type BoundaryInstallConfig struct {
	*hashicorp.InstallConfig
	ControllerEnabled bool
	WorkerEnabled     bool
	DatabaseURL       string
	ClusterAddr       string
	PublicAddr        string
	AuthMethodID      string
	RecoveryKmsType   string // "aead" for dev, "awskms", "gcpckms", "azurekeyvault" for prod
	KmsKeyID          string
	DevMode           bool
}

// NewNativeInstaller creates a new Boundary native installer
func NewNativeInstaller(rc *eos_io.RuntimeContext, config *BoundaryInstallConfig) *NativeInstaller {
	// Set defaults
	if config.InstallConfig == nil {
		config.InstallConfig = &hashicorp.InstallConfig{
			Product:       hashicorp.ProductBoundary,
			Version:       "latest",
			InstallMethod: hashicorp.MethodBinary,
			BinaryPath:    "/usr/local/bin/boundary",
			ConfigPath:    "/etc/boundary.d",
			DataPath:      "/opt/boundary/data",
			LogPath:       "/var/log/boundary",
			ServiceName:   "boundary",
			ServiceUser:   "boundary",
			ServiceGroup:  "boundary",
			Port:          shared.PortBoundary, // 9200 by default
			TLSEnabled:    true,
		}
	}

	// Set Boundary-specific defaults
	if !config.ControllerEnabled && !config.WorkerEnabled {
		// Default to controller in dev mode, both in prod
		if config.DevMode {
			config.ControllerEnabled = true
		} else {
			config.ControllerEnabled = true
			config.WorkerEnabled = true
		}
	}

	if config.ClusterAddr == "" {
		config.ClusterAddr = fmt.Sprintf("127.0.0.1:%d", shared.PortBoundary+1) // 9201
	}

	if config.PublicAddr == "" {
		config.PublicAddr = fmt.Sprintf("127.0.0.1:%d", shared.PortBoundary) // 9200
	}

	if config.RecoveryKmsType == "" {
		if config.DevMode {
			config.RecoveryKmsType = "aead"
		} else {
			config.RecoveryKmsType = "aead" // Default to simple AEAD
		}
	}

	baseInstaller := hashicorp.NewBaseInstaller(rc, hashicorp.ProductBoundary)

	return &NativeInstaller{
		BaseInstaller: baseInstaller,
		rc:            rc,
		config:        config,
	}
}

// Install performs the complete Boundary installation
func (n *NativeInstaller) Install() error {
	logger := otelzap.Ctx(n.rc.Ctx)

	// Initialize progress reporter
	steps := 8
	if n.config.DevMode {
		steps = 6 // Fewer steps in dev mode
	}
	progress := hashicorp.NewProgressReporter(logger, "Boundary Installation", steps)
	n.SetProgress(progress)

	// ASSESS - Check current status
	progress.Update("Checking current Boundary status")
	status, err := n.CheckStatus(n.config.InstallConfig)
	if err != nil {
		logger.Warn("Could not determine current Boundary status", zap.Error(err))
		status = &hashicorp.ProductStatus{}
	}

	// Check idempotency
	if status.Running && status.ConfigValid && !n.config.ForceReinstall {
		progress.Complete("Boundary is already installed and running")
		return nil
	}

	// Validate prerequisites
	progress.Update("Validating prerequisites")
	if err := n.validatePrerequisites(); err != nil {
		progress.Failed("Prerequisites validation failed", err)
		return fmt.Errorf("prerequisites validation failed: %w", err)
	}

	// Clean install if requested
	if n.config.CleanInstall {
		progress.Update("Performing clean installation")
		if err := n.CleanExistingInstallation(n.config.InstallConfig); err != nil {
			progress.Failed("Clean installation failed", err)
			return fmt.Errorf("failed to clean existing installation: %w", err)
		}
	}

	// INTERVENE - Install Boundary
	progress.Update("Installing Boundary binary")
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

	// Dev mode has simpler setup
	if n.config.DevMode {
		progress.Update("Setting up dev mode")
		if err := n.setupDevMode(); err != nil {
			progress.Failed("Dev mode setup failed", err)
			return fmt.Errorf("dev mode setup failed: %w", err)
		}
	} else {
		// Production setup
		// Create user
		progress.Update("Creating boundary user")
		if err := n.CreateUser(n.config.InstallConfig); err != nil {
			progress.Failed("User creation failed", err)
			return fmt.Errorf("failed to create boundary user: %w", err)
		}

		// Setup directories
		progress.Update("Setting up directories")
		if err := n.SetupDirectories(n.config.InstallConfig); err != nil {
			progress.Failed("Directory setup failed", err)
			return fmt.Errorf("failed to setup directories: %w", err)
		}

		// Configure Boundary
		progress.Update("Configuring Boundary")
		if err := n.configure(); err != nil {
			progress.Failed("Configuration failed", err)
			return fmt.Errorf("configuration failed: %w", err)
		}

		// Setup service
		progress.Update("Setting up systemd service")
		if err := n.setupService(); err != nil {
			progress.Failed("Service setup failed", err)
			return fmt.Errorf("service setup failed: %w", err)
		}

		// Initialize database if controller
		if n.config.ControllerEnabled && n.config.DatabaseURL != "" {
			progress.Update("Initializing database")
			if err := n.initializeDatabase(); err != nil {
				logger.Warn("Database initialization failed", zap.Error(err))
				// Non-fatal as it might already be initialized
			}
		}
	}

	// EVALUATE - Verify installation
	progress.Update("Verifying installation")
	if err := n.verify(); err != nil {
		progress.Failed("Verification failed", err)
		return fmt.Errorf("verification failed: %w", err)
	}

	progress.Complete("Boundary installation completed successfully")
	logger.Info("Boundary installation completed",
		zap.String("version", n.config.Version),
		zap.Int("port", n.config.Port),
		zap.Bool("controller", n.config.ControllerEnabled),
		zap.Bool("worker", n.config.WorkerEnabled),
		zap.Bool("dev_mode", n.config.DevMode))

	return nil
}

// validatePrerequisites performs Boundary-specific prerequisite checks
func (n *NativeInstaller) validatePrerequisites() error {
	if err := n.PreInstallValidation(n.config.InstallConfig); err != nil {
		return err
	}

	validator := hashicorp.NewValidator(otelzap.Ctx(n.rc.Ctx))

	// Check additional ports for Boundary
	validator.CheckPort(shared.PortBoundary + 1) // Cluster port
	validator.CheckPort(shared.PortBoundary + 2) // Ops port

	// Check for PostgreSQL if controller mode and not dev
	if n.config.ControllerEnabled && !n.config.DevMode && n.config.DatabaseURL == "" {
		validator.RequireCommand("psql")
	}

	if validator.HasErrors() {
		return validator.GetError()
	}

	return nil
}

// configure writes the Boundary configuration
func (n *NativeInstaller) configure() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Configuring Boundary")

	// Backup existing configuration
	configFile := filepath.Join(n.config.ConfigPath, "boundary.hcl")
	n.GetFileManager().BackupFile(configFile)

	// Generate KMS configuration
	var kmsConfig string
	switch n.config.RecoveryKmsType {
	case "awskms":
		kmsConfig = fmt.Sprintf(`
kms "awskms" {
  purpose    = "root"
  region     = "us-east-1"
  kms_key_id = "%s"
}

kms "awskms" {
  purpose    = "worker-auth"
  region     = "us-east-1"
  kms_key_id = "%s"
}`, n.config.KmsKeyID, n.config.KmsKeyID)
	default: // aead
		kmsConfig = `
kms "aead" {
  purpose = "root"
  aead_type = "aes-gcm"
  key = "sP1fnF5Xz85RrXVuTZpEkslRvH35QIYG0zXNmB8jKQI="
  key_id = "global_root"
}

kms "aead" {
  purpose = "worker-auth"
  aead_type = "aes-gcm"
  key = "lJMASVb3vXVlRBV4kN0gPckKDlM65DwUfD6b6T2HqkI="
  key_id = "global_worker-auth"
}

kms "aead" {
  purpose = "recovery"
  aead_type = "aes-gcm"
  key = "qLrUtmJoZ1UCJ8vU9MDiZf9Vh3VlnQb8MkBjVVuLfas="
  key_id = "global_recovery"
}`
	}

	// Generate controller configuration if enabled
	var controllerConfig string
	if n.config.ControllerEnabled {
		controllerConfig = fmt.Sprintf(`
controller {
  name = "boundary-controller"
  description = "Boundary controller managed by Eos"
  
  database {
    url = "%s"
    max_open_connections = 5
  }
  
  public_cluster_addr = "%s"
}`, n.config.DatabaseURL, n.config.ClusterAddr)
	}

	// Generate worker configuration if enabled
	var workerConfig string
	if n.config.WorkerEnabled {
		workerConfig = fmt.Sprintf(`
worker {
  name = "boundary-worker"
  description = "Boundary worker managed by Eos"
  
  public_addr = "%s"
  
  initial_upstreams = ["%s"]
  
  tags {
    type = ["generic", "docker"]
  }
}`, n.config.PublicAddr, n.config.ClusterAddr)
	}

	// Generate complete configuration
	config := fmt.Sprintf(`# Boundary configuration managed by Eos
disable_mlock = true

listener "tcp" {
  address = "0.0.0.0:%d"
  purpose = "api"
  tls_disable = %t
}

listener "tcp" {
  address = "0.0.0.0:%d"
  purpose = "cluster"
  tls_disable = %t
}

listener "tcp" {
  address = "127.0.0.1:%d"
  purpose = "ops"
  tls_disable = true
}
%s
%s
%s

events {
  audit_enabled       = true
  observations_enable = true
  sysevents_enabled   = true
}

`, n.config.Port, !n.config.TLSEnabled,
		shared.PortBoundary+1, !n.config.TLSEnabled,
		shared.PortBoundary+2,
		kmsConfig, controllerConfig, workerConfig)

	// Write configuration
	if err := n.GetFileManager().WriteWithOwnership(
		configFile,
		[]byte(config),
		0640,
		n.config.ServiceUser,
		n.config.ServiceGroup,
	); err != nil {
		return fmt.Errorf("failed to write configuration: %w", err)
	}

	logger.Info("Boundary configuration written successfully")
	return nil
}

// setupService creates and starts the systemd service
func (n *NativeInstaller) setupService() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Setting up Boundary systemd service")

	// Determine service type
	serviceType := "server"
	if n.config.WorkerEnabled && !n.config.ControllerEnabled {
		serviceType = "worker"
	}

	// Write systemd service file
	serviceContent := fmt.Sprintf(`[Unit]
Description=HashiCorp Boundary
Documentation=https://www.boundaryproject.io/docs/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=%s/boundary.hcl

[Service]
Type=notify
User=%s
Group=%s
ExecStart=%s %s -config=%s
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
`, n.config.ConfigPath, n.config.ServiceUser, n.config.ServiceGroup,
		n.config.BinaryPath, serviceType, n.config.ConfigPath)

	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", n.config.ServiceName)
	if err := n.GetFileManager().WriteWithOwnership(
		servicePath,
		[]byte(serviceContent),
		0644,
		"root",
		"root",
	); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// Reload systemd
	if err := n.GetSystemd().ReloadDaemon(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Enable service
	if err := n.GetSystemd().EnableService(n.config.ServiceName); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	// Start service
	logger.Info("Starting Boundary service")
	if err := n.GetSystemd().StartService(n.config.ServiceName); err != nil {
		// Get service status for debugging
		if status, statusErr := n.GetSystemd().GetServiceStatus(n.config.ServiceName); statusErr == nil {
			logger.Error("Failed to start Boundary service",
				zap.String("status", status))
		}
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}

// setupDevMode sets up Boundary in development mode
func (n *NativeInstaller) setupDevMode() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Setting up Boundary in development mode")

	// Create a simple dev script
	devScript := fmt.Sprintf(`#!/bin/bash
# Boundary dev mode launcher managed by Eos

%s dev \
  -api-listen-address="0.0.0.0:%d" \
  -cluster-listen-address="0.0.0.0:%d" \
  -proxy-listen-address="0.0.0.0:%d" \
  -log-level=debug
`, n.config.BinaryPath, n.config.Port, shared.PortBoundary+1, shared.PortBoundary+3)

	scriptPath := "/usr/local/bin/boundary-dev"
	if err := n.GetFileManager().WriteWithOwnership(
		scriptPath,
		[]byte(devScript),
		0755,
		"root",
		"root",
	); err != nil {
		return fmt.Errorf("failed to write dev script: %w", err)
	}

	logger.Info("Boundary dev mode setup complete",
		zap.String("script", scriptPath))
	logger.Info("terminal prompt: To start Boundary in dev mode, run: boundary-dev")

	return nil
}

// initializeDatabase initializes the Boundary database
func (n *NativeInstaller) initializeDatabase() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Initializing Boundary database")

	// Run database init
	if err := n.GetRunner().Run(
		n.config.BinaryPath,
		"database", "init",
		"-config", n.config.ConfigPath,
	); err != nil {
		return fmt.Errorf("database initialization failed: %w", err)
	}

	logger.Info("Boundary database initialized successfully")
	return nil
}

// verify checks that Boundary is working correctly
func (n *NativeInstaller) verify() error {
	logger := otelzap.Ctx(n.rc.Ctx)
	logger.Info("Verifying Boundary installation")

	// Check if binary works
	if err := n.GetRunner().Run(n.config.BinaryPath, "version"); err != nil {
		return fmt.Errorf("Boundary binary not working: %w", err)
	}

	if !n.config.DevMode {
		// Wait for service to stabilize
		maxRetries := 10
		for i := 1; i <= maxRetries; i++ {
			if n.GetSystemd().IsServiceActive(n.config.ServiceName) {
				break
			}

			if i == maxRetries {
				return fmt.Errorf("Boundary service failed to start after %d attempts", maxRetries)
			}

			logger.Debug("Waiting for Boundary service",
				zap.Int("attempt", i),
				zap.Int("max_retries", maxRetries))
			time.Sleep(time.Duration(i) * time.Second)
		}
	}

	logger.Info("Boundary verification successful")
	return nil
}
