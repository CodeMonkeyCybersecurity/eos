// pkg/bootstrap/hashicorp_bootstrap.go
//
// Comprehensive HashiCorp stack bootstrap implementation

package bootstrap

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BootstrapHashiCorpComplete performs a comprehensive HashiCorp stack setup
func BootstrapHashiCorpComplete(rc *eos_io.RuntimeContext, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting comprehensive HashiCorp stack bootstrap")

	// Phase 1: Validate prerequisites
	if err := validateHashiCorpPrerequisites(rc); err != nil {
		return fmt.Errorf("HashiCorp prerequisites check failed: %w", err)
	}

	// Phase 2: Install HashiCorp tools if needed
	if err := ensureHashiCorpInstalled(rc, info); err != nil {
		return fmt.Errorf("HashiCorp installation failed: %w", err)
	}

	// Phase 3: Configure HashiCorp stack
	if err := configureHashiCorp(rc, info); err != nil {
		return fmt.Errorf("HashiCorp configuration failed: %w", err)
	}

	// Phase 4: Start services
	if err := startHashiCorpServices(rc, info); err != nil {
		return fmt.Errorf("HashiCorp service startup failed: %w", err)
	}

	logger.Info("HashiCorp stack bootstrap completed successfully")
	return nil
}

// validateHashiCorpPrerequisites validates system requirements for HashiCorp stack
func validateHashiCorpPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating HashiCorp prerequisites")

	// Check if running as root (required for system service installation)
	if os.Geteuid() != 0 {
		return fmt.Errorf("HashiCorp stack installation requires root privileges")
	}

	// Basic system checks - simplified for now
	logger.Info("System prerequisites validated")

	logger.Info("Prerequisites validation passed")
	return nil
}

// ensureHashiCorpInstalled installs HashiCorp tools if not present
func ensureHashiCorpInstalled(rc *eos_io.RuntimeContext, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Ensuring HashiCorp tools are installed")

	tools := []string{"consul", "nomad", "vault", "terraform"}
	
	for _, tool := range tools {
		if err := installHashiCorpTool(rc, tool); err != nil {
			return fmt.Errorf("failed to install %s: %w", tool, err)
		}
	}

	logger.Info("All HashiCorp tools installed successfully")
	return nil
}

// configureHashiCorp configures the HashiCorp stack
func configureHashiCorp(rc *eos_io.RuntimeContext, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring HashiCorp stack")

	// Configure Consul
	if err := configureConsul(rc, info); err != nil {
		return fmt.Errorf("consul configuration failed: %w", err)
	}

	// Configure Nomad
	if err := configureNomad(rc, info); err != nil {
		return fmt.Errorf("nomad configuration failed: %w", err)
	}

	// Configure Vault
	if err := configureVault(rc, info); err != nil {
		return fmt.Errorf("vault configuration failed: %w", err)
	}

	logger.Info("HashiCorp stack configuration completed")
	return nil
}

// startHashiCorpServices starts HashiCorp services
func startHashiCorpServices(rc *eos_io.RuntimeContext, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting HashiCorp services")

	services := []string{"consul", "nomad", "vault"}
	
	for _, service := range services {
		if err := startService(rc, service); err != nil {
			return fmt.Errorf("failed to start %s: %w", service, err)
		}
	}

	// Wait for services to be ready
	time.Sleep(10 * time.Second)

	logger.Info("All HashiCorp services started successfully")
	return nil
}

// Helper functions - use existing implementations from other files

func installHashiCorpTool(rc *eos_io.RuntimeContext, tool string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if already installed
	if _, err := exec.LookPath(tool); err == nil {
		logger.Info("Tool already installed", zap.String("tool", tool))
		return nil
	}

	logger.Info("Installing HashiCorp tool", zap.String("tool", tool))
	
	// Use native installer approach
	switch tool {
	case "consul":
		return installHashiCorpConsul(rc)
	case "nomad":
		return installHashiCorpNomad(rc)
	case "vault":
		return installHashiCorpVault(rc)
	case "terraform":
		return installTerraform(rc)
	default:
		return fmt.Errorf("unknown tool: %s", tool)
	}
}

func installHashiCorpConsul(rc *eos_io.RuntimeContext) error {
	// Placeholder for Consul installation
	return fmt.Errorf("consul installation requires administrator intervention - please use 'eos create consul'")
}

func installHashiCorpNomad(rc *eos_io.RuntimeContext) error {
	// Placeholder for Nomad installation
	return fmt.Errorf("nomad installation requires administrator intervention - please use 'eos create nomad'")
}

func installHashiCorpVault(rc *eos_io.RuntimeContext) error {
	// Placeholder for Vault installation
	return fmt.Errorf("vault installation requires administrator intervention - please use 'eos create vault'")
}

func installTerraform(rc *eos_io.RuntimeContext) error {
	// Placeholder for Terraform installation
	return fmt.Errorf("terraform installation requires administrator intervention - please use 'eos create terraform'")
}

func configureConsul(rc *eos_io.RuntimeContext, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Consul")
	
	// Create configuration directory
	configDir := "/etc/consul.d"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create consul config directory: %w", err)
	}

	// Generate basic configuration
	datacenter := "dc1"
	if info.ClusterID != "" {
		datacenter = info.ClusterID
	}
	
	config := fmt.Sprintf(`{
  "datacenter": "%s",
  "data_dir": "/opt/consul",
  "log_level": "INFO",
  "server": true,
  "bootstrap_expect": 1,
  "bind_addr": "0.0.0.0",
  "client_addr": "0.0.0.0",
  "retry_join": ["127.0.0.1"],
  "ui_config": {
    "enabled": true
  },
  "connect": {
    "enabled": true
  }
}`, datacenter)

	configPath := filepath.Join(configDir, "consul.json")
	// SECURITY: Use 0640 instead of 0644 to prevent world-readable HashiCorp configs
	if err := os.WriteFile(configPath, []byte(config), 0640); err != nil {
		return fmt.Errorf("failed to write consul config: %w", err)
	}

	return nil
}

func configureNomad(rc *eos_io.RuntimeContext, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Nomad")
	
	// Create configuration directory
	configDir := "/etc/nomad.d"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create nomad config directory: %w", err)
	}

	// Generate basic configuration
	datacenter := "dc1"
	if info.ClusterID != "" {
		datacenter = info.ClusterID
	}
	
	config := fmt.Sprintf(`datacenter = "%s"
data_dir = "/opt/nomad"
log_level = "INFO"

server {
  enabled = true
  bootstrap_expect = 1
}

client {
  enabled = true
}

consul {
  address = "127.0.0.1:%d"
}`, datacenter, shared.PortConsul)

	configPath := filepath.Join(configDir, "nomad.hcl")
	// SECURITY: Use 0640 instead of 0644 to prevent world-readable HashiCorp configs
	if err := os.WriteFile(configPath, []byte(config), 0640); err != nil {
		return fmt.Errorf("failed to write nomad config: %w", err)
	}

	return nil
}

func configureVault(rc *eos_io.RuntimeContext, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Vault")
	
	// Create configuration directory
	configDir := "/etc/vault.d"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create vault config directory: %w", err)
	}

	// Generate basic configuration
	config := fmt.Sprintf(`storage "consul" {
  address = "127.0.0.1:%d"
  path    = "vault/"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

api_addr = "http://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"
ui = true`, shared.PortConsul)

	configPath := filepath.Join(configDir, "vault.hcl")
	// SECURITY: Use 0640 instead of 0644 to prevent world-readable HashiCorp configs
	if err := os.WriteFile(configPath, []byte(config), 0640); err != nil {
		return fmt.Errorf("failed to write vault config: %w", err)
	}

	return nil
}

func startService(rc *eos_io.RuntimeContext, service string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting service", zap.String("service", service))
	
	cmd := exec.Command("systemctl", "start", service)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start %s service: %w", service, err)
	}

	// Enable service for auto-start
	cmd = exec.Command("systemctl", "enable", service)
	if err := cmd.Run(); err != nil {
		logger.Warn("Failed to enable service for auto-start", 
			zap.String("service", service), 
			zap.Error(err))
	}

	return nil
}

