// pkg/vault/lifecycle2_enable.go

package vault

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func VaultAddress() string {
	return os.Getenv(shared.VaultAddrEnv)
}

// EnableVault performs Vault initialization and enablement (Phases 5-15)
//
// Prerequisites: Call NewVaultInstaller().Install() first to complete Phases 1-4
//
// Complete Phase Breakdown:
//   Phase 1-4: Handled by install.go (Install() method)
//     Phase 1: Binary installation and user/directory creation
//     Phase 2: Environment setup (VAULT_ADDR, VAULT_CACERT, agent directories)
//     Phase 3: TLS certificate generation
//     Phase 4: Configuration file generation (vault.hcl)
//
//   Phase 5-15: Handled by this function (EnableVault)
//     Phase 5: Service startup (happens in cmd/create/secrets.go before calling EnableVault)
//     Phase 6a: Vault initialization (UnsealVault)
//     Phase 6b: Vault unseal (UnsealVault)
//     Phase 7: Root token verification (PhasePromptAndVerRootToken)
//     Phase 7a: API client verification (GetRootClient)
//     Phase 8: Health check (PhaseEnsureVaultHealthy)
//     Phase 9a: KV v2 secrets engine (PhaseEnableKVv2)
//     Phase 9d: Additional secrets engines - Database, PKI (PhaseEnableSecretsEngines)
//     Phase 9e: Activity tracking enablement (PhaseEnableTracking)
//     Phase 9b: Bootstrap secret verification (PhaseWriteBootstrapSecretAndRecheck)
//     Phase 10a: Userpass authentication (PhaseEnableUserpass) - optional, interactive
//     Phase 10b: AppRole authentication (PhaseEnableAppRole) - optional, interactive
//     Phase 10c: Entity and alias creation (PhaseCreateEosEntity)
//     Phase 11: Policy configuration (EnsurePolicy)
//     Phase 12: Audit logging (EnableFileAudit)
//     Phase 13: Multi-Factor Authentication (EnableMFAMethods) - optional, interactive
//     Phase 14: Vault Agent service (PhaseEnableVaultAgent) - optional, interactive
//     Phase 15: Comprehensive hardening (ComprehensiveHardening) - optional, interactive
//
// Interactive phases (10a, 10b, 13, 14, 15) prompt the user for confirmation.
func EnableVault(rc *eos_io.RuntimeContext, client *api.Client, log *zap.Logger) error {
	log.Info(" Starting Vault enablement flow (Phases 5-15)")

	// Fall back to direct enablement
	log.Info("Nomad not available, using direct enablement")

	// Clear any existing VAULT_TOKEN to ensure fresh authentication setup
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		log.Info(" Clearing existing VAULT_TOKEN environment variable for fresh setup")
		if err := os.Unsetenv("VAULT_TOKEN"); err != nil {
			log.Warn("Failed to unset VAULT_TOKEN", zap.Error(err))
		}
		log.Info(" VAULT_TOKEN cleared successfully")
	} else {
		log.Info(" No existing VAULT_TOKEN found - proceeding with fresh setup")
	}

	log.Info(" Starting Vault initialization and unseal process")
	unsealedClient, err := UnsealVault(rc)
	if err != nil {
		return logger.LogErrAndWrap(rc, "initialize and unseal vault", err)
	}
	client = unsealedClient
	log.Info(" Vault client initialized and unsealed successfully")

	steps := []struct {
		name string
		fn   func() error
	}{
		{"verify root token", func() error { return PhasePromptAndVerRootToken(rc, client) }},
		{"verify vault API client", func() error { _, err := GetRootClient(rc); return err }},
		{"verify vault healthy (Phase 8)", func() error { return PhaseEnsureVaultHealthy(rc) }},
	}
	for _, step := range steps {
		otelzap.Ctx(rc.Ctx).Info(fmt.Sprintf(" %s...", step.name))
		if err := step.fn(); err != nil {
			return logger.LogErrAndWrap(rc, step.name, err)
		}
	}

	// Step 9a: Enable KV v2
	log.Info(" Enabling KV v2 secrets engine")
	if err := PhaseEnableKVv2(rc, client); err != nil {
		log.Error(" Failed to enable KV v2 secrets engine", zap.Error(err))
		return logger.LogErrAndWrap(rc, "enable KV v2", err)
	}
	log.Info(" KV v2 secrets engine enabled successfully")

	// Step 9d: Enable additional secrets engines (database, PKI)
	log.Info(" Enabling additional secrets engines")
	if err := PhaseEnableSecretsEngines(rc, client); err != nil {
		log.Error(" Failed to enable additional secrets engines", zap.Error(err))
		return logger.LogErrAndWrap(rc, "enable additional secrets engines", err)
	}
	log.Info(" Additional secrets engines phase completed")

	// Step 9e: Enable activity tracking
	log.Info(" Enabling activity tracking")
	if err := PhaseEnableTracking(rc, client); err != nil {
		log.Warn(" Failed to enable activity tracking (non-fatal)", zap.Error(err))
		log.Info("terminal prompt: Activity tracking could not be enabled automatically")
		log.Info("terminal prompt: You can enable it later with: vault write sys/internal/counters/config enabled=enable")
	} else {
		log.Info(" Activity tracking enabled successfully")
	}

	// Step 10a: interactively configure userpass auth
	userpassConfigured, err := IsUserpassConfigured(rc, client)
	if err != nil {
		log.Warn("Failed to check userpass status, will prompt", zap.Error(err))
		userpassConfigured = false // Default to prompting on error
	}

	if userpassConfigured {
		log.Info("terminal prompt: ✓ Userpass authentication already configured")
		if interaction.PromptYesNo(rc.Ctx, "  Rotate eos user password?", false) {
			password, err := crypto.PromptPassword(rc, "Enter NEW password for Eos Vault user:")
			if err != nil {
				return logger.LogErrAndWrap(rc, "prompt password", err)
			}
			if err := UpdateUserpassPassword(rc, client, password); err != nil {
				return logger.LogErrAndWrap(rc, "rotate password", err)
			}
			log.Info("terminal prompt: ✓ Password rotated successfully")
		}
	} else {
		if interaction.PromptYesNo(rc.Ctx, "Enable Userpass authentication?", false) {
			// empty password => will prompt internally
			if err := PhaseEnableUserpass(rc, client, log, ""); err != nil {
				return logger.LogErrAndWrap(rc, "enable Userpass", err)
			}
		}
	}

	// Step 10b: interactively configure AppRole auth
	approleConfigured, err := IsAppRoleConfigured(rc, client)
	if err != nil {
		log.Warn("Failed to check AppRole status, will prompt", zap.Error(err))
		approleConfigured = false // Default to prompting on error
	}

	if approleConfigured {
		log.Info("terminal prompt: ✓ AppRole authentication already configured")
		if interaction.PromptYesNo(rc.Ctx, "  Regenerate AppRole credentials?", false) {
			if err := RegenerateAppRoleCredentials(rc, client); err != nil {
				return logger.LogErrAndWrap(rc, "regenerate approle credentials", err)
			}
			log.Info("terminal prompt: ✓ AppRole credentials regenerated successfully")
		}
	} else {
		if interaction.PromptYesNo(rc.Ctx, "Enable AppRole authentication?", false) {
			opts := shared.DefaultAppRoleOptions()
			if err := PhaseEnableAppRole(rc, client, log, opts); err != nil {
				return logger.LogErrAndWrap(rc, "enable AppRole", err)
			}
		}
	}

	// Step 10c: Create Eos entity and aliases
	if err := PhaseCreateEosEntity(rc); err != nil {
		return logger.LogErrAndWrap(rc, "create eos entity", err)
	}

	// Step 11: Write core policies
	if err := EnsurePolicy(rc); err != nil {
		return logger.LogErrAndWrap(rc, "write policies", err)
	}

	// Step 12: Enable comprehensive audit logging
	if err := EnableFileAudit(rc, client); err != nil {
		return logger.LogErrAndWrap(rc, "enable audit backend", err)
	}

	// Step 13: Configure Multi-Factor Authentication
	if interaction.PromptYesNo(rc.Ctx, "Enable Multi-Factor Authentication (MFA)?", true) {
		mfaConfig := DefaultMFAConfig()
		if err := EnableMFAMethods(rc, client, mfaConfig); err != nil {
			return logger.LogErrAndWrap(rc, "enable MFA", err)
		}
		log.Info(" MFA configuration completed")
	} else {
		log.Warn("MFA was not enabled - this reduces security")
	}

	// Step 14: Vault Agent comprehensive enablement
	agentConfigured, err := IsAgentConfigured(rc)
	if err != nil {
		log.Warn("Failed to check Agent status, will prompt", zap.Error(err))
		agentConfigured = false // Default to prompting on error
	}

	if agentConfigured {
		log.Info("terminal prompt: ✓ Vault Agent already configured")
		if interaction.PromptYesNo(rc.Ctx, "  Reconfigure Vault Agent?", false) {
			log.Info(" Starting Vault Agent reconfiguration")
			config := DefaultVaultAgentConfig()
			if err := PhaseEnableVaultAgent(rc, client, config); err != nil {
				return logger.LogErrAndWrap(rc, "reconfigure Vault Agent", err)
			}
		}
	} else if interaction.PromptYesNo(rc.Ctx, "Enable Vault Agent service?", true) {
		log.Info(" Starting Vault Agent enablement")
		config := DefaultVaultAgentConfig()
		if err := PhaseEnableVaultAgent(rc, client, config); err != nil {
			return logger.LogErrAndWrap(rc, "enable Vault Agent", err)
		}
		log.Info(" Vault Agent enabled successfully")
		log.Info("terminal prompt: Vault Agent is now running and configured for automatic authentication")
	} else {
		log.Info("⏭️ Vault Agent enablement skipped by user")
		log.Info("terminal prompt: Vault Agent not enabled. You can enable it later with manual configuration.")
	}

	// Step 15: Apply core secrets and verify readiness
	if err := PhaseWriteBootstrapSecretAndRecheck(rc, client); err != nil {
		return logger.LogErrAndWrap(rc, "apply core secrets", err)
	}

	// Step 16: Optional Phase 15 - Comprehensive Hardening
	if interaction.PromptYesNo(rc.Ctx, "Apply comprehensive security hardening (Phase 15)?", true) {
		log.Info(" [Phase 15] Starting comprehensive hardening")
		hardeningConfig := DefaultHardeningConfig()

		// Ask user if they want to customize hardening
		if interaction.PromptYesNo(rc.Ctx, "Use default hardening settings (recommended for production)?", true) {
			log.Info(" Using default hardening configuration")
		} else {
			log.Info(" Skipping some aggressive hardening steps")
			// Disable some more aggressive options if user wants to customize
			hardeningConfig.RevokeRootToken = interaction.PromptYesNo(rc.Ctx, "Revoke root token? (Ensure alternative auth works first)", false)
			hardeningConfig.DisableSwap = interaction.PromptYesNo(rc.Ctx, "Disable swap for security?", true)
			hardeningConfig.ConfigureFirewall = interaction.PromptYesNo(rc.Ctx, "Configure firewall rules?", true)
		}

		if err := ComprehensiveHardening(rc, client, hardeningConfig); err != nil {
			log.Warn("Comprehensive hardening failed (non-fatal)", zap.Error(err))
			log.Info("terminal prompt: Some hardening steps failed. You can retry with: eos secure vault --comprehensive")
		} else {
			log.Info(" [Phase 15] Comprehensive hardening completed successfully")
			log.Info("terminal prompt: Vault has been hardened for production use")
		}
	} else {
		log.Info("⏭️ [Phase 15] Hardening skipped by user")
		log.Info("terminal prompt: IMPORTANT: Run 'eos secure vault --comprehensive' before production use")
	}

	log.Info(" Vault enablement process completed successfully")
	PrintEnableNextSteps(rc)
	return nil
}

func PrintEnableNextSteps(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("terminal prompt: Vault setup is now complete!")
	logger.Info("Next steps completed",
		zap.Strings("next_steps", []string{
			"Run: eos secure vault (to finalize hardening and cleanup)",
			"Test Vault Agent: eos read vault agent",
			"Optionally onboard new users, configure roles, or deploy additional services",
		}))
}
