package nomad

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SaltInstaller provides Salt-based Nomad installation
type SaltInstaller struct {
	logger     otelzap.LoggerWithCtx
	saltClient *saltstack.Client
}

// NewSaltInstaller creates a new Salt-based Nomad installer
func NewSaltInstaller(logger otelzap.LoggerWithCtx) *SaltInstaller {
	return &SaltInstaller{
		logger:     logger,
		saltClient: saltstack.NewClient(logger),
	}
}

// SaltNomadConfig holds Salt-specific Nomad configuration
// This replaces K3s configuration for container orchestration
type SaltNomadConfig struct {
	Version         string
	ServerMode      bool
	ClientMode      bool
	Datacenter      string
	Region          string
	BootstrapExpect int
	ACLEnabled      bool
	TLSEnabled      bool
	ConsulEnabled   bool
	ConsulAddress   string
	VaultEnabled    bool
	VaultAddress    string
	VaultToken      string
	VaultCACert     string
	VaultRole       string
	NetworkInterface string
	EnableRawExec   bool
	DockerEnabled   bool
	DockerVolumesEnabled bool
	DockerAllowPrivileged bool
	TelemetryEnabled bool
	TelemetryInterval string
	PrometheusMetrics bool
	HTTPPort        int
	RPCPort         int
	SerfPort        int
	Servers         []string
	EncryptionKey   string
	
	// Migration-specific fields for K3s replacement
	IngressDomain   string   `json:"ingress_domain,omitempty"`
	EnableIngress   bool     `json:"enable_ingress"`
	EnableMailProxy bool     `json:"enable_mail_proxy"`
	MailPorts       []int    `json:"mail_ports,omitempty"`
	MigratedFromK3s bool     `json:"migrated_from_k3s"`
}

// InstallNomadViaSalt installs Nomad using Salt states
func (si *SaltInstaller) InstallNomadViaSalt(rc *eos_io.RuntimeContext, config *SaltNomadConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Nomad installation via Salt states")

	// ASSESS - Check prerequisites
	logger.Info("Assessing Nomad installation prerequisites")
	
	// Set default configuration
	if config == nil {
		config = si.getDefaultConfig()
	}

	// Ensure Salt is available
	if err := si.verifySaltAvailability(rc); err != nil {
		return fmt.Errorf("Salt verification failed: %w", err)
	}

	// INTERVENE - Install via Salt states
	logger.Info("Installing Nomad via Salt states")
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Minute)
	defer cancel()

	// Apply Salt state
	if err := si.applySaltState(ctx, config); err != nil {
		return fmt.Errorf("Salt state application failed: %w", err)
	}

	// EVALUATE - Verify installation
	logger.Info("Verifying Nomad installation")
	
	if err := si.verifyInstallation(ctx); err != nil {
		return fmt.Errorf("installation verification failed: %w", err)
	}

	logger.Info("Nomad installation via Salt completed successfully")
	return nil
}

// getDefaultConfig returns default Nomad configuration
func (si *SaltInstaller) getDefaultConfig() *SaltNomadConfig {
	return &SaltNomadConfig{
		Version:         "latest",
		ServerMode:      true,
		ClientMode:      true,
		Datacenter:      "dc1",
		Region:          "global",
		BootstrapExpect: 1,
		ACLEnabled:      false,
		TLSEnabled:      false,
		ConsulEnabled:   false,
		ConsulAddress:   "127.0.0.1:8500",
		VaultEnabled:    false,
		VaultAddress:    "https://127.0.0.1:8200",
		VaultRole:       "nomad-cluster",
		NetworkInterface: "eth0",
		EnableRawExec:   false,
		DockerEnabled:   true,
		DockerVolumesEnabled: true,
		DockerAllowPrivileged: false,
		TelemetryEnabled: false,
		TelemetryInterval: "1s",
		PrometheusMetrics: false,
		HTTPPort:        4646,
		RPCPort:         4647,
		SerfPort:        4648,
		Servers:         []string{"127.0.0.1:4647"},
	}
}

// verifySaltAvailability checks if Salt is available
func (si *SaltInstaller) verifySaltAvailability(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if salt-call is available
	result, err := si.saltClient.CmdRunLocal(rc.Ctx, "which salt-call")
	if err != nil {
		return fmt.Errorf("salt-call not found: %w", err)
	}
	
	logger.Info("Salt availability verified", zap.String("salt_path", result))
	return nil
}

// applySaltState applies the Nomad Salt state
func (si *SaltInstaller) applySaltState(ctx context.Context, config *SaltNomadConfig) error {
	logger := otelzap.Ctx(ctx)
	
	// Prepare pillar data
	pillarData := map[string]interface{}{
		"nomad": map[string]interface{}{
			"version":                    config.Version,
			"server_mode":                config.ServerMode,
			"client_mode":                config.ClientMode,
			"datacenter":                 config.Datacenter,
			"region":                     config.Region,
			"bootstrap_expect":           config.BootstrapExpect,
			"acl_enabled":                config.ACLEnabled,
			"tls_enabled":                config.TLSEnabled,
			"consul_enabled":             config.ConsulEnabled,
			"consul_address":             config.ConsulAddress,
			"vault_enabled":              config.VaultEnabled,
			"vault_address":              config.VaultAddress,
			"vault_token":                config.VaultToken,
			"vault_ca_cert":              config.VaultCACert,
			"vault_role":                 config.VaultRole,
			"network_interface":          config.NetworkInterface,
			"enable_raw_exec":            config.EnableRawExec,
			"docker_enabled":             config.DockerEnabled,
			"docker_volumes_enabled":     config.DockerVolumesEnabled,
			"docker_allow_privileged":    config.DockerAllowPrivileged,
			"telemetry_enabled":          config.TelemetryEnabled,
			"telemetry_interval":         config.TelemetryInterval,
			"prometheus_metrics":         config.PrometheusMetrics,
			"http_port":                  config.HTTPPort,
			"rpc_port":                   config.RPCPort,
			"serf_port":                  config.SerfPort,
			"servers":                    config.Servers,
			"encrypt_key":                config.EncryptionKey,
		},
	}

	logger.Info("Applying Nomad Salt state", zap.Any("pillar", pillarData))
	
	// Apply the state
	if err := si.saltClient.StateApplyLocal(ctx, "hashicorp.nomad", pillarData); err != nil {
		return fmt.Errorf("failed to apply nomad state: %w", err)
	}

	return nil
}

// verifyInstallation verifies that Nomad was installed correctly
func (si *SaltInstaller) verifyInstallation(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)
	
	// Check if Nomad binary exists
	if _, err := si.saltClient.CmdRunLocal(ctx, "which nomad"); err != nil {
		return fmt.Errorf("nomad binary not found: %w", err)
	}
	
	// Check if service is enabled
	if _, err := si.saltClient.CmdRunLocal(ctx, "systemctl is-enabled nomad"); err != nil {
		logger.Warn("Nomad service not enabled", zap.Error(err))
	}
	
	// Check if service is running
	if _, err := si.saltClient.CmdRunLocal(ctx, "systemctl is-active nomad"); err != nil {
		logger.Warn("Nomad service not running", zap.Error(err))
		// Don't fail here as service might not be started yet
	}
	
	// Check Nomad version
	if result, err := si.saltClient.CmdRunLocal(ctx, "nomad version"); err != nil {
		logger.Warn("Failed to check Nomad version", zap.Error(err))
	} else {
		logger.Info("Nomad version check passed", zap.String("version", result))
	}
	
	logger.Info("Nomad installation verification completed")
	return nil
}

// StartNomadService starts the Nomad service
func (si *SaltInstaller) StartNomadService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Nomad service")
	
	// Enable service
	if _, err := si.saltClient.CmdRunLocal(rc.Ctx, "systemctl enable nomad"); err != nil {
		return fmt.Errorf("failed to enable nomad service: %w", err)
	}
	
	// Start service
	if _, err := si.saltClient.CmdRunLocal(rc.Ctx, "systemctl start nomad"); err != nil {
		return fmt.Errorf("failed to start nomad service: %w", err)
	}
	
	logger.Info("Nomad service started successfully")
	return nil
}

// StopNomadService stops the Nomad service
func (si *SaltInstaller) StopNomadService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Stopping Nomad service")
	
	// Stop service
	if _, err := si.saltClient.CmdRunLocal(rc.Ctx, "systemctl stop nomad"); err != nil {
		return fmt.Errorf("failed to stop nomad service: %w", err)
	}
	
	// Disable service
	if _, err := si.saltClient.CmdRunLocal(rc.Ctx, "systemctl disable nomad"); err != nil {
		return fmt.Errorf("failed to disable nomad service: %w", err)
	}
	
	logger.Info("Nomad service stopped successfully")
	return nil
}

// GetNomadStatus gets the current status of Nomad
func (si *SaltInstaller) GetNomadStatus(rc *eos_io.RuntimeContext) (map[string]interface{}, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Getting Nomad status")
	
	status := make(map[string]interface{})
	
	// Check if binary exists
	if _, err := si.saltClient.CmdRunLocal(rc.Ctx, "which nomad"); err != nil {
		status["binary_installed"] = false
	} else {
		status["binary_installed"] = true
	}
	
	// Check service status
	if result, err := si.saltClient.CmdRunLocal(rc.Ctx, "systemctl is-active nomad"); err != nil {
		status["service_active"] = false
	} else {
		status["service_active"] = result == "active"
	}
	
	// Check if service is enabled
	if result, err := si.saltClient.CmdRunLocal(rc.Ctx, "systemctl is-enabled nomad"); err != nil {
		status["service_enabled"] = false
	} else {
		status["service_enabled"] = result == "enabled"
	}
	
	// Get version if available
	if result, err := si.saltClient.CmdRunLocal(rc.Ctx, "nomad version"); err == nil {
		status["version"] = result
	}
	
	return status, nil
}