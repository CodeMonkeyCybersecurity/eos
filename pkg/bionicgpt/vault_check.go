// Package bionicgpt provides Vault prerequisite validation
//
// This module validates that Vault is available and healthy before deployment starts.
// Following shift-left principles: fail fast with actionable error messages.
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package bionicgpt

import (
	"context"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
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

	// Check 3: Vault is reachable
	statusOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"status", "-format=json"},
		Capture: true,
	})

	// Vault status returns exit code 2 when sealed, 0 when unsealed
	// We accept both - just need Vault to be running
	if err != nil && !strings.Contains(statusOutput, "sealed") && !strings.Contains(statusOutput, "initialized") {
		return eos_err.NewUserError(
			"Vault is not reachable at %s\n\n"+
				"Error: %v\n\n"+
				"Troubleshooting:\n"+
				"  1. Check Vault is running: systemctl status vault\n"+
				"  2. Start Vault: sudo systemctl start vault\n"+
				"  3. Debug Vault: eos debug vault\n"+
				"  4. View logs: sudo journalctl -u vault -n 50\n\n"+
				"If Vault is not installed:\n"+
				"  sudo eos create vault",
			vaultAddr, err)
	}

	logger.Debug("✓ Vault is reachable")

	// Check 4: Vault Agent token exists (used by Eos for authentication)
	vaultAgentTokenPath := "/run/eos/vault_agent_eos.token"
	if _, err := os.Stat(vaultAgentTokenPath); os.IsNotExist(err) {
		return eos_err.NewUserError(
			"Vault Agent token not found\n\n"+
				"BionicGPT uses Vault Agent for secret retrieval.\n\n"+
				"Missing file: %s\n\n"+
				"Troubleshooting:\n"+
				"  1. Check Vault Agent is running: systemctl status vault-agent-eos\n"+
				"  2. Restart Vault Agent: sudo systemctl restart vault-agent-eos\n"+
				"  3. Debug Vault: eos debug vault\n"+
				"  4. View logs: sudo journalctl -u vault-agent-eos -n 50\n\n"+
				"If Vault Agent is not set up:\n"+
				"  sudo eos create vault",
			vaultAgentTokenPath)
	}

	logger.Debug("✓ Vault Agent token exists", zap.String("path", vaultAgentTokenPath))

	// Check 5: Can authenticate with Vault
	vaultToken := readVaultAgentToken(rc.Ctx, vaultAgentTokenPath)

	// Set VAULT_TOKEN environment variable for this command
	lookupOpts := execute.Options{
		Command: "vault",
		Args:    []string{"token", "lookup"},
		Capture: true,
	}

	// Note: We'll authenticate by using the token from file
	// Vault CLI will read VAULT_TOKEN from environment or -token flag
	tokenFlag := []string{"token", "lookup", "-token=" + vaultToken}
	lookupOpts.Args = tokenFlag

	_, err = execute.Run(rc.Ctx, lookupOpts)

	if err != nil {
		return eos_err.NewUserError(
			"Cannot authenticate with Vault\n\n" +
				"Vault Agent token may be expired or invalid.\n\n" +
				"Troubleshooting:\n" +
				"  1. Restart Vault Agent: sudo systemctl restart vault-agent-eos\n" +
				"  2. Debug Vault: eos debug vault\n" +
				"  3. Check Vault policies: vault token lookup\n\n" +
				"If authentication continues to fail:\n" +
				"  sudo eos create vault --force")
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
