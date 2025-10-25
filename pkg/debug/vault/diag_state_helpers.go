// pkg/debug/vault/diag_state_helpers.go
// Helper functions for Vault state diagnostics

package vault

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// getVaultBinaryVersion gets the version from the Vault binary
// This reads the binary's version information without shelling out
func getVaultBinaryVersion(ctx context.Context, binaryPath string) (string, error) {
	logger := otelzap.Ctx(ctx)

	// We still need to execute the binary to get version, but we do it
	// in a controlled way with proper error handling
	versionCmd := exec.CommandContext(ctx, binaryPath, "version")
	versionOut, err := versionCmd.Output()
	if err != nil {
		logger.Debug("Failed to get vault version",
			zap.String("binary_path", binaryPath),
			zap.Error(err))
		return "", fmt.Errorf("failed to get version: %w", err)
	}

	return strings.TrimSpace(string(versionOut)), nil
}

// checkVaultInitialized checks if Vault is initialized using the API client
func checkVaultInitialized(ctx context.Context) (bool, error) {
	logger := otelzap.Ctx(ctx)

	// Get Vault address from environment
	vaultAddr := shared.GetVaultAddrWithEnv()

	// Create Vault API client config
	config := vaultapi.DefaultConfig()
	config.Address = vaultAddr

	// Handle self-signed certificates
	tlsConfig := &vaultapi.TLSConfig{
		Insecure: true,
	}
	if err := config.ConfigureTLS(tlsConfig); err != nil {
		logger.Debug("Failed to configure TLS", zap.Error(err))
		return false, fmt.Errorf("failed to configure TLS: %w", err)
	}

	// Create client
	client, err := vaultapi.NewClient(config)
	if err != nil {
		logger.Debug("Failed to create Vault client", zap.Error(err))
		return false, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Check initialization status using sys/init endpoint
	initStatus, err := client.Sys().InitStatus()
	if err != nil {
		logger.Debug("Failed to check init status", zap.Error(err))
		return false, fmt.Errorf("failed to check init status: %w", err)
	}

	logger.Debug("Vault init status checked via API",
		zap.Bool("initialized", initStatus))

	return initStatus, nil
}
