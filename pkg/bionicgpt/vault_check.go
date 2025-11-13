// Package bionicgpt provides Vault prerequisite validation
//
// This module validates that Vault is available and healthy before deployment starts.
// Following shift-left principles: fail fast with actionable error messages.
//
// REFACTORED: Now uses Vault SDK instead of shelling out for performance and security
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package bionicgpt

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ValidateVaultAvailable checks that Vault is installed, running, and accessible
// Returns user-friendly error with remediation steps if Vault is not available
func ValidateVaultAvailable(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Validating Vault prerequisite")

	// Check 1: Vault CLI installed
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"--version"},
		Capture: true,
	})
	if err != nil {
		return eos_err.NewUserError(
			"Vault CLI not found\n\n" +
				"BionicGPT requires HashiCorp Vault for secrets management.\n\n" +
				"Install Vault:\n" +
				"  sudo eos create vault\n\n" +
				"Or install manually:\n" +
				"  https://developer.hashicorp.com/vault/install")
	}

	logger.Debug("✓ Vault CLI installed")

	// Check 2: VAULT_ADDR environment variable set
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		return eos_err.NewUserError(
			"VAULT_ADDR environment variable not set\n\n" +
				"BionicGPT needs to know where Vault is running.\n\n" +
				"If Vault is running locally:\n" +
				"  export VAULT_ADDR=https://localhost:8200\n\n" +
				"If Vault is not installed:\n" +
				"  sudo eos create vault")
	}

	logger.Debug("✓ VAULT_ADDR set", zap.String("addr", vaultAddr))

	// Check 3: Vault is reachable and healthy (using SDK)
	// REFACTORED: Use vault.CheckVaultSealStatusUnauthenticated() instead of shelling out
	// This uses the /v1/sys/seal-status endpoint which is unauthenticated and fast
	initialized, sealed, err := vault.CheckVaultSealStatusUnauthenticated(rc)
	if err != nil {
		return eos_err.NewUserError(
			"Vault is not reachable at %s\n\n"+
				"Error: %v\n\n"+
				"Troubleshooting:\n"+
				"  1. Check Vault is running: systemctl status vault\n"+
				"  2. Start Vault: sudo systemctl start vault\n"+
				"  3. Debug Vault: eos debug vault --agent\n"+
				"  4. View logs: sudo journalctl -u vault -n 50\n\n"+
				"If Vault is not installed:\n"+
				"  sudo eos create vault",
			vaultAddr, err)
	}

	if !initialized {
		return eos_err.NewUserError(
			"Vault is not initialized at %s\n\n"+
				"Initialize Vault:\n"+
				"  sudo eos create vault",
			vaultAddr)
	}

	if sealed {
		return eos_err.NewUserError(
			"Vault is sealed at %s\n\n"+
				"Unseal Vault:\n"+
				"  vault operator unseal\n"+
				"  (Enter unseal keys when prompted)\n\n"+
				"Or debug:\n"+
				"  sudo eos debug vault",
			vaultAddr)
	}

	logger.Debug("✓ Vault is reachable and unsealed")

	// Check 4: Vault Agent token exists (used by Eos for authentication)
	// Use shared constant instead of hardcoded path
	vaultAgentTokenPath := shared.AgentToken
	if _, err := os.Stat(vaultAgentTokenPath); os.IsNotExist(err) {
		return eos_err.NewUserError(
			"Vault Agent token not found\n\n"+
				"BionicGPT uses Vault Agent for secret retrieval.\n\n"+
				"Missing file: %s\n\n"+
				"Troubleshooting:\n"+
				"  1. Check Vault Agent is running: systemctl status vault-agent-eos\n"+
				"  2. Restart Vault Agent: sudo systemctl restart vault-agent-eos\n"+
				"  3. Debug Vault Agent: sudo eos debug vault --agent\n"+
				"  4. View logs: sudo journalctl -u vault-agent-eos -n 50\n\n"+
				"If Vault Agent is not set up:\n"+
				"  sudo eos create vault",
			vaultAgentTokenPath)
	}

	logger.Debug("✓ Vault Agent token file exists", zap.String("path", vaultAgentTokenPath))

	// Check 5: Can authenticate with Vault (using SDK)
	// REFACTORED: Use Vault SDK instead of shelling out 'vault token lookup'
	// This is faster, more secure, and provides better error diagnostics
	vaultToken := readVaultAgentToken(rc.Ctx, vaultAgentTokenPath)
	if vaultToken == "" {
		return eos_err.NewUserError(
			"Vault Agent token file is empty\n\n"+
				"Vault Agent has not authenticated yet.\n\n"+
				"Token file: %s\n\n"+
				"Troubleshooting:\n"+
				"  1. Check Vault Agent logs: sudo journalctl -u vault-agent-eos -n 50\n"+
				"  2. Restart Vault Agent: sudo systemctl restart vault-agent-eos\n"+
				"  3. Debug Vault Agent: sudo eos debug vault --agent\n\n"+
				"Common causes:\n"+
				"  - AppRole credentials missing or invalid\n"+
				"  - Vault Agent service failed to start\n"+
				"  - Network connectivity to Vault\n"+
				"  - Vault sealed or not initialized",
			vaultAgentTokenPath)
	}

	// Create Vault client
	client, err := vault.GetVaultClient(rc)
	if err != nil {
		return eos_err.NewUserError(
			"Failed to create Vault client\n\n"+
				"Error: %v\n\n"+
				"Troubleshooting:\n"+
				"  1. Check VAULT_ADDR is correct: echo $VAULT_ADDR\n"+
				"  2. Check Vault is reachable: curl -k $VAULT_ADDR/v1/sys/health\n"+
				"  3. Debug Vault: sudo eos debug vault --agent",
			err)
	}

	// Set token from Vault Agent
	client.SetToken(vaultToken)

	// Validate token by calling LookupSelf (same as 'vault token lookup')
	tokenInfo, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return eos_err.NewUserError(
			"Cannot authenticate with Vault\n\n"+
				"Vault Agent token may be expired or invalid.\n\n"+
				"Error: %v\n\n"+
				"Troubleshooting:\n"+
				"  1. Restart Vault Agent: sudo systemctl restart vault-agent-eos\n"+
				"  2. Debug Vault Agent: sudo eos debug vault --agent\n"+
				"  3. Check token status: vault token lookup\n\n"+
				"If authentication continues to fail:\n"+
				"  sudo eos update vault --agent",
			err)
	}

	// Check token TTL (time-to-live)
	// If TTL is too low, token might expire during operation
	ttlRaw, hasTTL := tokenInfo.Data["ttl"]
	if hasTTL {
		var ttlSeconds int64
		switch v := ttlRaw.(type) {
		case json.Number:
			ttlSeconds, _ = v.Int64()
		case float64:
			ttlSeconds = int64(v)
		case int:
			ttlSeconds = int64(v)
		case int64:
			ttlSeconds = v
		}

		const minRequiredTTL = 60 // 1 minute minimum
		if ttlSeconds > 0 && ttlSeconds < minRequiredTTL {
			return eos_err.NewUserError(
				"Vault token TTL too low (%d seconds remaining)\n\n"+
					"Token will expire soon. Waiting for Vault Agent to renew...\n\n"+
					"Troubleshooting:\n"+
					"  1. Wait 10 seconds and try again (Agent may be renewing)\n"+
					"  2. Restart Vault Agent: sudo systemctl restart vault-agent-eos\n"+
					"  3. Debug Vault Agent: sudo eos debug vault --agent\n\n"+
					"Token info:\n"+
					"  TTL: %d seconds\n"+
					"  Required: %d seconds minimum",
				ttlSeconds, ttlSeconds, minRequiredTTL)
		}

		logger.Debug("✓ Vault token valid",
			zap.Int64("ttl_seconds", ttlSeconds),
			zap.String("policies", fmt.Sprintf("%v", tokenInfo.Data["policies"])))
	}

	logger.Info("✓ Vault is available and accessible")

	return nil
}

// readVaultAgentToken reads the Vault Agent token from file
func readVaultAgentToken(ctx context.Context, path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
