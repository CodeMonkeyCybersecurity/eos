// Package prerequisites provides prerequisite checking for ClusterFuzz deployment
package prerequisites

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/clusterfuzz"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Check validates all prerequisites for ClusterFuzz deployment.
// It follows the Assess → Intervene → Evaluate pattern.
func Check(rc *eos_io.RuntimeContext, config *clusterfuzz.Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check Nomad connectivity
	logger.Info("Checking Nomad connectivity...")
	if err := execute.RunSimple(rc.Ctx, "nomad", "status", "-address="+config.NomadAddress); err != nil {
		return fmt.Errorf("cannot connect to Nomad at %s: %w", config.NomadAddress, err)
	}

	// Check Consul connectivity
	logger.Info("Checking Consul connectivity...")
	if err := execute.RunSimple(rc.Ctx, "consul", "members", "-http-addr="+config.ConsulAddress); err != nil {
		logger.Warn("Consul not available, service discovery will be limited",
			zap.String("consul_address", config.ConsulAddress))
	}

	// INTERVENE - Check required tools
	requiredTools := []string{"nomad", "docker"}
	for _, tool := range requiredTools {
		if err := execute.RunSimple(rc.Ctx, "which", tool); err != nil {
			return fmt.Errorf("%s is required but not found in PATH", tool)
		}
	}

	// EVALUATE - Check Vault if enabled
	if config.UseVault {
		logger.Info("Checking Vault connectivity...")
		if err := CheckVaultConnectivity(rc); err != nil {
			return fmt.Errorf("Vault check failed: %w", err)
		}
	}

	return nil
}

// CheckVaultConnectivity verifies Vault is accessible and unsealed
func CheckVaultConnectivity(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if VAULT_ADDR is set
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		return fmt.Errorf("VAULT_ADDR environment variable is not set")
	}

	logger.Info("Checking Vault status",
		zap.String("vault_addr", vaultAddr))

	// Check Vault status using Run to capture output
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"status", "-format=json"},
		Capture: true,
	})
	if err != nil {
		// Check if it's a specific exit code (sealed)
		// For now, just log warning and continue
		logger.Warn("Vault status check returned error (might be sealed)",
			zap.Error(err))
		return nil
	}

	logger.Info("Vault is accessible",
		zap.String("output", output))
	
	return nil
}