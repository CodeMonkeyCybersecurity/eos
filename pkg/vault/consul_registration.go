// pkg/vault/consul_registration.go
// Consul service registration for Vault

package vault

import (
	"fmt"
	"os"

	"go.uber.org/zap"
)

// registerWithConsul registers Vault instance with Consul for service discovery
// This is idempotent - safe to call multiple times
func (vi *VaultInstaller) registerWithConsul() error {
	logger := vi.logger

	logger.Info("Attempting to register Vault with Consul")

	// ASSESS - Check if Consul is available
	discovery, err := NewVaultDiscovery(vi.rc, vi.config.Datacenter)
	if err != nil {
		logger.Debug("Consul not available, skipping registration",
			zap.Error(err))
		return nil // Not an error - Consul may not be installed yet
	}

	// Determine Vault address
	// Use WireGuard IP if available, otherwise use localhost
	vaultAddress := "127.0.0.1"
	if vi.config.BindAddr != "" && vi.config.BindAddr != "0.0.0.0" {
		vaultAddress = vi.config.BindAddr
	}

	// Get hostname for node name
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "vault-server"
	}

	// Get Vault version
	version := "unknown"
	if output, err := vi.runner.RunOutput(vi.config.BinaryPath, "version"); err == nil {
		version = parseVaultVersion(output)
	}

	// Prepare registration
	registration := VaultRegistration{
		NodeName:      hostname,
		Address:       vaultAddress,
		Port:          vi.config.Port,
		Version:       version,
		Tags:          []string{"active"}, // Add 'active' tag for service discovery
		TLSSkipVerify: !vi.config.TLSEnabled,
	}

	// INTERVENE - Register with Consul
	logger.Info("Registering Vault with Consul",
		zap.String("address", vaultAddress),
		zap.Int("port", vi.config.Port),
		zap.String("datacenter", vi.config.Datacenter))

	if err := discovery.RegisterVault(vi.rc.Ctx, registration); err != nil {
		return fmt.Errorf("failed to register with Consul: %w", err)
	}

	// EVALUATE - Verify registration
	logger.Info("Vault successfully registered with Consul",
		zap.String("service_id", fmt.Sprintf("vault-%s", hostname)),
		zap.String("datacenter", vi.config.Datacenter))

	logger.Info("terminal prompt:  Vault registered with Consul for service discovery")
	logger.Info(fmt.Sprintf("terminal prompt: Services can now discover Vault at: vault.service.%s.consul", vi.config.Datacenter))

	return nil
}

// parseVaultVersion extracts version from 'vault version' output
func parseVaultVersion(output string) string {
	// Output format: "Vault v1.15.0 (deadbeef), built 2023-10-10T00:00:00Z"
	// Extract just the version number
	if len(output) > 7 && output[:6] == "Vault " {
		// Find first space after version
		for i := 7; i < len(output); i++ {
			if output[i] == ' ' {
				return output[7:i]
			}
		}
	}
	return "unknown"
}
