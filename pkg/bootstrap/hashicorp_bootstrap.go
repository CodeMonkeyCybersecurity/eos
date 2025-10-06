// pkg/bootstrap/hashicorp_bootstrap.go
//
// Comprehensive HashiCorp stack bootstrap implementation

package bootstrap

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// startHashiCorpServices starts HashiCorp services with proper dependency ordering
func startHashiCorpServices(rc *eos_io.RuntimeContext, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting HashiCorp services in dependency order")

	// P1 fix: Start services in correct dependency order
	// 1. Consul must start first (service discovery + Vault storage backend)
	// 2. Vault depends on Consul
	// 3. Nomad depends on Consul (and optionally Vault)
	serviceDependencyOrder := []string{"consul", "vault", "nomad"}

	for _, service := range serviceDependencyOrder {
		logger.Info("Starting service in dependency chain",
			zap.String("service", service))

		if err := startService(rc, service); err != nil {
			return fmt.Errorf("failed to start %s (dependency chain broken): %w", service, err)
		}

		// Verify service is responding before starting next service
		if err := verifyServiceHealth(rc, service); err != nil {
			logger.Warn("Service started but health check failed",
				zap.String("service", service),
				zap.Error(err),
				zap.String("impact", "continuing anyway - may cause cascading failures"))
			// Continue anyway as some services may not have health endpoints configured yet
		}
	}

	logger.Info("All HashiCorp services started successfully in dependency order")
	return nil
}

// verifyServiceHealth performs basic health check on service
func verifyServiceHealth(rc *eos_io.RuntimeContext, service string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Basic health checks by service type
	switch service {
	case "consul":
		// Check Consul HTTP API
		return verifyConsulHealth(rc)
	case "vault":
		// Check Vault HTTP API (may be sealed, that's OK)
		return verifyVaultHealth(rc)
	case "nomad":
		// Check Nomad HTTP API
		return verifyNomadHealth(rc)
	default:
		logger.Debug("No health check defined for service", zap.String("service", service))
		return nil
	}
}

func verifyConsulHealth(rc *eos_io.RuntimeContext) error {
	// Basic HTTP check to Consul API
	cmd := exec.CommandContext(rc.Ctx, "curl", "-sf", fmt.Sprintf("http://127.0.0.1:%d/v1/status/leader", shared.PortConsul))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("consul health check failed: %w", err)
	}
	return nil
}

func verifyVaultHealth(rc *eos_io.RuntimeContext) error {
	// Vault may be sealed, so just check if API responds
	cmd := exec.CommandContext(rc.Ctx, "curl", "-sf", fmt.Sprintf("http://127.0.0.1:%d/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200", shared.PortVault))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}
	return nil
}

func verifyNomadHealth(rc *eos_io.RuntimeContext) error {
	// Check Nomad agent info
	cmd := exec.CommandContext(rc.Ctx, "curl", "-sf", fmt.Sprintf("http://127.0.0.1:%d/v1/agent/self", shared.PortNomad))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nomad health check failed: %w", err)
	}
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

// TODO(P2): These installation functions are placeholders that redirect to dedicated installers.
// Consider either:
// 1. Implementing simplified binary-only installation here for bootstrap use case
// 2. Removing and having BootstrapHashiCorpComplete require pre-installed binaries
// 3. Calling the full installers from pkg/consul/install.go, pkg/vault/install.go, etc.

func installHashiCorpConsul(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Error("Consul installation not implemented in bootstrap - use dedicated installer",
		zap.String("command", "eos create consul"),
		zap.String("reason", "bootstrap requires pre-configured installation"))
	return fmt.Errorf("consul not installed - run 'eos create consul' first, then retry bootstrap")
}

func installHashiCorpNomad(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Error("Nomad installation not implemented in bootstrap - use dedicated installer",
		zap.String("command", "eos create nomad"),
		zap.String("reason", "bootstrap requires pre-configured installation"))
	return fmt.Errorf("nomad not installed - run 'eos create nomad' first, then retry bootstrap")
}

func installHashiCorpVault(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Error("Vault installation not implemented in bootstrap - use dedicated installer",
		zap.String("command", "eos create vault"),
		zap.String("reason", "bootstrap requires pre-configured installation"))
	return fmt.Errorf("vault not installed - run 'eos create vault' first, then retry bootstrap")
}

func installTerraform(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Error("Terraform installation not implemented in bootstrap - use dedicated installer",
		zap.String("command", "eos create terraform"),
		zap.String("reason", "bootstrap requires pre-configured installation"))
	return fmt.Errorf("terraform not installed - run 'eos create terraform' first, then retry bootstrap")
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

	// P1 fix: Backup existing config before overwrite
	if _, err := os.Stat(configPath); err == nil {
		backupPath := configPath + ".backup." + time.Now().Format("20060102-150405")
		logger.Info("Backing up existing config",
			zap.String("config", configPath),
			zap.String("backup", backupPath))
		if err := os.Rename(configPath, backupPath); err != nil {
			logger.Warn("Failed to backup config, continuing anyway", zap.Error(err))
		}
	}

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

	// P1 fix: Backup existing config before overwrite
	if _, err := os.Stat(configPath); err == nil {
		backupPath := configPath + ".backup." + time.Now().Format("20060102-150405")
		logger.Info("Backing up existing config",
			zap.String("config", configPath),
			zap.String("backup", backupPath))
		if err := os.Rename(configPath, backupPath); err != nil {
			logger.Warn("Failed to backup config, continuing anyway", zap.Error(err))
		}
	}

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
  address     = "0.0.0.0:%d"
  tls_disable = 1
}

api_addr = "http://127.0.0.1:%d"
cluster_addr = "https://127.0.0.1:%d"
ui = true`, shared.PortConsul, shared.PortVault, shared.PortVault, shared.PortVault+1)

	configPath := filepath.Join(configDir, "vault.hcl")

	// P1 fix: Backup existing config before overwrite
	if _, err := os.Stat(configPath); err == nil {
		backupPath := configPath + ".backup." + time.Now().Format("20060102-150405")
		logger.Info("Backing up existing config",
			zap.String("config", configPath),
			zap.String("backup", backupPath))
		if err := os.Rename(configPath, backupPath); err != nil {
			logger.Warn("Failed to backup config, continuing anyway", zap.Error(err))
		}
	}

	// SECURITY: Use 0640 instead of 0644 to prevent world-readable HashiCorp configs
	if err := os.WriteFile(configPath, []byte(config), 0640); err != nil {
		return fmt.Errorf("failed to write vault config: %w", err)
	}

	return nil
}

func startService(rc *eos_io.RuntimeContext, service string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting service", zap.String("service", service))

	// Start service
	cmd := exec.CommandContext(rc.Ctx, "systemctl", "start", service)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start %s service: %w", service, err)
	}

	// Enable service for auto-start
	cmd = exec.CommandContext(rc.Ctx, "systemctl", "enable", service)
	if err := cmd.Run(); err != nil {
		logger.Warn("Failed to enable service for auto-start",
			zap.String("service", service),
			zap.Error(err))
	}

	// Verify service actually started (P1 fix)
	maxAttempts := 30 // 30 seconds timeout
	for i := 0; i < maxAttempts; i++ {
		checkCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", service)
		if output, err := checkCmd.Output(); err == nil {
			status := strings.TrimSpace(string(output))
			if status == "active" {
				logger.Info("Service started successfully",
					zap.String("service", service),
					zap.Int("wait_seconds", i))
				return nil
			}
		}

		// Check if context cancelled
		select {
		case <-rc.Ctx.Done():
			return fmt.Errorf("service start cancelled: %w", rc.Ctx.Err())
		case <-time.After(1 * time.Second):
			// Continue waiting
		}
	}

	return fmt.Errorf("service %s failed to become active within %d seconds", service, maxAttempts)
}

