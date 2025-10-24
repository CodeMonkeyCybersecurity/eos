// pkg/consul/install_orchestrator.go
// Clean orchestrator for Consul installation - coordinates all modules

package lifecycle

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/helpers"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/rollback"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/service"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/validation"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Orchestrator coordinates all installation modules
// Note: InstallConfig is defined in install.go
type Orchestrator struct {
	rc            *eos_io.RuntimeContext
	config        *InstallConfig
	logger        otelzap.LoggerWithCtx
	versionMgr    *VersionManager
	binaryInst    *BinaryInstaller
	repoInst      *RepositoryInstaller
	validator     *validation.PrerequisitesValidator
	configSetup   *config.SetupManager
	lifecycle     *service.LifecycleManager
	rollbackMgr   *rollback.RollbackManager
	networkHelper *helpers.NetworkHelper
}

// NewOrchestrator creates a new installation orchestrator
func NewOrchestrator(rc *eos_io.RuntimeContext, cfg *InstallConfig) (*Orchestrator, error) {
	// Set defaults
	if cfg.Version == "" {
		cfg.Version = "latest"
	}
	if cfg.Datacenter == "" {
		cfg.Datacenter = "dc1"
	}
	if cfg.BinaryPath == "" {
		cfg.BinaryPath = "/usr/bin/consul"
	}
	if cfg.ClientAddr == "" {
		cfg.ClientAddr = "0.0.0.0"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "INFO"
	}

	logger := otelzap.Ctx(rc.Ctx)

	// Detect bind address if not specified
	networkHelper := helpers.NewNetworkHelper(rc)
	if cfg.BindAddr == "" {
		bindAddr, err := networkHelper.GetDefaultBindAddr()
		if err != nil {
			return nil, fmt.Errorf("failed to detect bind address: %w\nPlease specify --bind-addr explicitly", err)
		}
		cfg.BindAddr = bindAddr
	}

	return &Orchestrator{
		rc:            rc,
		config:        cfg,
		logger:        logger,
		versionMgr:    NewVersionManager(rc),
		binaryInst:    NewBinaryInstaller(rc, cfg.BinaryPath),
		repoInst:      NewRepositoryInstaller(rc),
		validator:     validation.NewPrerequisitesValidator(rc),
		configSetup:   config.NewSetupManager(rc, cfg.BinaryPath),
		lifecycle:     service.NewLifecycleManager(rc),
		rollbackMgr:   rollback.NewRollbackManager(rc, cfg.BinaryPath),
		networkHelper: networkHelper,
	}, nil
}

// Install performs the complete Consul installation
func (o *Orchestrator) Install() error {
	o.logger.Info("Starting Consul installation",
		zap.String("version", o.config.Version),
		zap.String("datacenter", o.config.Datacenter),
		zap.Bool("use_repository", o.config.UseRepository))

	// Track installation state for rollback
	state := rollback.InstallationState{
		UseRepository: o.config.UseRepository,
	}

	// CRITICAL: Rollback on failure
	installComplete := false
	defer func() {
		if !installComplete {
			o.logger.Warn("Installation failed, attempting rollback")
			_ = o.rollbackMgr.RollbackPartialInstall(state)
		}
	}()

	// Phase 1: ASSESS - Check if already installed
	o.logger.Info("[16%] Checking current Consul status")
	if shouldInstall, err := o.assess(); err != nil {
		return fmt.Errorf("assessment failed: %w", err)
	} else if !shouldInstall {
		o.logger.Info("Consul is already installed and running properly")
		installComplete = true
		return nil
	}

	// Phase 2: Validate prerequisites
	o.logger.Info("[33%] Validating prerequisites")
	requiredPorts := []int{shared.PortConsul, 8300, 8301, 8302, 8502, 8600}
	if err := o.validator.ValidateAll(requiredPorts); err != nil {
		return fmt.Errorf("prerequisite validation failed: %w", err)
	}
	if err := o.validator.ValidateConfig(o.config.Version, o.config.Datacenter, o.config.BindAddr); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Phase 3: INTERVENE - Install binary
	o.logger.Info("[50%] Installing Consul binary")
	version, err := o.versionMgr.ResolveVersion(o.config.Version)
	if err != nil {
		return fmt.Errorf("version resolution failed: %w", err)
	}

	if o.config.UseRepository {
		if err := o.repoInst.Install(version); err != nil {
			return fmt.Errorf("repository installation failed: %w", err)
		}
	} else {
		if err := o.binaryInst.Install(version); err != nil {
			return fmt.Errorf("binary installation failed: %w", err)
		}
	}
	state.BinaryInstalled = true

	// Phase 4: Configure
	o.logger.Info("[66%] Configuring Consul")
	if err := o.configSetup.SetupDirectories(); err != nil {
		return fmt.Errorf("directory setup failed: %w", err)
	}
	if err := o.configSetup.CreateLogrotateConfig(); err != nil {
		o.logger.Warn("Failed to create logrotate config", zap.Error(err))
	}
	
	// Generate configuration using existing config package
	consulConfig := &config.ConsulConfig{
		DatacenterName:     o.config.Datacenter,
		EnableDebugLogging: o.config.LogLevel == "DEBUG",
		VaultAvailable:     o.config.VaultIntegration,
		BootstrapExpect:    o.config.BootstrapExpect,
	}
	if err := config.Generate(o.rc, consulConfig); err != nil {
		return fmt.Errorf("configuration generation failed: %w", err)
	}
	if err := o.configSetup.ValidateConfiguration("/etc/consul.d"); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}
	state.ConfigCreated = true

	// Phase 5: Setup service
	o.logger.Info("[83%] Setting up systemd service")
	if err := o.lifecycle.Enable(); err != nil {
		return fmt.Errorf("service enable failed: %w", err)
	}
	if err := o.lifecycle.Start(); err != nil {
		return fmt.Errorf("service start failed: %w", err)
	}
	state.ServiceCreated = true

	// Phase 6: EVALUATE - Verify
	o.logger.Info("[100%] Verifying installation")
	if !o.lifecycle.IsReady() {
		return fmt.Errorf("consul is not ready after installation")
	}

	o.logger.Info("Consul installation completed successfully",
		zap.String("version", version),
		zap.String("datacenter", o.config.Datacenter),
		zap.String("bind_addr", o.config.BindAddr))

	installComplete = true
	return nil
}

// assess checks if Consul is already installed and running
func (o *Orchestrator) assess() (bool, error) {
	// Check if already running and healthy
	if o.lifecycle.IsActive() && o.lifecycle.IsReady() {
		if !o.config.ForceReinstall {
			o.logger.Info("Consul is already installed and running properly")
			return false, nil // Don't install
		}
		o.logger.Info("Force reinstall requested")
	}

	// Clean install if requested
	if o.config.CleanInstall {
		if err := o.rollbackMgr.CleanExistingInstallation(); err != nil {
			return false, fmt.Errorf("failed to clean existing installation: %w", err)
		}
	}

	return true, nil // Proceed with installation
}
