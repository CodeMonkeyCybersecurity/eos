// pkg/vault/phase4_config.go

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// Render, Write, Validate Vault Configuration vault.hcl
//--------------------------------------------------------------------

func WriteAndValidateConfig(rc *eos_io.RuntimeContext) error {
	if err := PhaseEnsureVaultConfigExists(rc); err != nil {
		return err
	}
	if err := PhasePatchVaultConfigIfNeeded(rc); err != nil {
		return err
	}
	if err := ValidateVaultConfig(rc); err != nil {
		return err
	}
	return nil
}

// PhaseEnsureVaultConfigExists ensures that Vault's server config exists or writes a default.
func PhaseEnsureVaultConfigExists(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info(" Checking if Vault config exists", zap.String("path", shared.VaultConfigPath))
	if _, err := os.Stat(shared.VaultConfigPath); os.IsNotExist(err) {
		otelzap.Ctx(rc.Ctx).Warn("Vault config missing — generating default vault.hcl", zap.String("path", shared.VaultConfigPath))
		if err := WriteVaultHCL(rc); err != nil {
			otelzap.Ctx(rc.Ctx).Error(" Failed to write vault.hcl", zap.Error(err))
			return fmt.Errorf("write vault.hcl: %w", err)
		}
		otelzap.Ctx(rc.Ctx).Info(" Default vault.hcl written successfully", zap.String("path", shared.VaultConfigPath))
	} else if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Error checking vault config", zap.Error(err))
		return fmt.Errorf("check vault config: %w", err)
	} else {
		otelzap.Ctx(rc.Ctx).Info(" Vault config already present", zap.String("path", shared.VaultConfigPath))
	}
	return nil
}

// PhasePatchVaultConfigIfNeeded detects legacy port 8200 and patches to 8179 if needed.
func PhasePatchVaultConfigIfNeeded(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info(" Checking for Vault port mismatch (8200 → 8179)", zap.String("path", shared.VaultConfigPath))

	data, err := os.ReadFile(shared.VaultConfigPath)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Could not read vault config file — skipping patch", zap.Error(err))
		return nil
	}
	content := string(data)

	if strings.Contains(content, shared.VaultDefaultPort) {
		otelzap.Ctx(rc.Ctx).Info(" Vault already configured for port 8179 — no patch needed")
		return nil
	}

	if !strings.Contains(content, "8200") {
		otelzap.Ctx(rc.Ctx).Info(" No 8200 port found in config — no patch needed")
		return nil
	}

	otelzap.Ctx(rc.Ctx).Warn(" Detected legacy port 8200 — patching to 8179")

	// Replace and rewrite
	newContent := strings.ReplaceAll(content, "8200", shared.VaultDefaultPort)
	// SECURITY: Use 0640 not 0644 to prevent world-readable config file
	if err := os.WriteFile(shared.VaultConfigPath, []byte(newContent), shared.RuntimeFilePerms); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to patch vault.hcl", zap.Error(err))
		return fmt.Errorf("failed to patch vault config: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault config patched to 8179 — manual Vault restart required", zap.String("path", shared.VaultConfigPath))
	return nil
}

// ValidateVaultConfig validates Vault configuration using Vault binary itself.
func ValidateVaultConfig(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info(" Validating vault.hcl", zap.String("path", shared.VaultConfigPath))

	info, err := os.Stat(shared.VaultConfigPath)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Vault config file not found", zap.Error(err))
		return fmt.Errorf("vault config missing: %w", err)
	}
	if info.Size() == 0 {
		otelzap.Ctx(rc.Ctx).Error(" Vault config file is empty")
		return fmt.Errorf("vault config file empty")
	}

	// Optionally: simple keyword checks
	expected := []string{"listener", "storage", "api_addr"}
	content, err := os.ReadFile(shared.VaultConfigPath)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to read config", zap.Error(err))
		return fmt.Errorf("read config failed: %w", err)
	}
	for _, keyword := range expected {
		if !strings.Contains(string(content), keyword) {
			otelzap.Ctx(rc.Ctx).Warn("Vault config missing expected keyword", zap.String("keyword", keyword))
		}
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault configuration validated successfully")
	return nil
}

// WriteVaultHCL renders the Vault server configuration (HCL) dynamically
// and writes it to the expected config file on disk. Ensures the directory exists.
// Returns a wrapped error if writing fails.
//
// UPDATED: Now defaults to Consul storage backend (recommended by HashiCorp)
// Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/consul
func WriteVaultHCL(rc *eos_io.RuntimeContext) error {
	vaultAddr := shared.GetVaultAddr()
	// Add sane defaults
	logLevel := "info"
	logFormat := "json"

	// Use Consul storage backend (recommended)
	// Provides HA without Raft complexity
	params := shared.VaultConfigParams{
		Port:          shared.VaultDefaultPort,
		ClusterPort:   shared.VaultClusterPort,
		TLSCrt:        shared.TLSCrt,
		TLSKey:        shared.TLSKey,
		APIAddr:       vaultAddr,
		ClusterAddr:   shared.GetVaultDefaultClusterAddr(),
		LogLevel:      logLevel,
		LogFormat:     logFormat,
		// Consul backend configuration
		ConsulAddress: shared.GetConsulDefaultAddr(),
		ConsulPath:    "vault/",
		ConsulScheme:  "http",
	}

	hcl, err := shared.RenderVaultConfigConsul(params)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to render Vault HCL config", zap.Error(err))
		return fmt.Errorf("render vault config: %w", err)
	}

	configPath := shared.VaultConfigPath // /etc/vault.d/vault.hcl

	// Guarantee the parent directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		otelzap.Ctx(rc.Ctx).Error("failed to create Vault config directory", zap.String("path", dir), zap.Error(err))
		return fmt.Errorf("mkdir vault config dir: %w", err)
	}
	otelzap.Ctx(rc.Ctx).Debug(" Vault config directory ready", zap.String("path", dir))

	// Safely write the Vault config
	// SECURITY: Use 0640 instead of 0644 to prevent world-readable config
	// Vault configs may contain sensitive paths, storage backend details, etc.
	if err := os.WriteFile(configPath, []byte(hcl), 0640); err != nil {
		otelzap.Ctx(rc.Ctx).Error("failed to write Vault HCL config", zap.Error(err))
		return fmt.Errorf("write vault hcl: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault configuration written", zap.String("path", configPath))
	return nil
}
