// pkg/vault/lifecycle2_enable.go

package vault

import (
	"fmt"
	"os"
	"time"

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
//
//	Phase 1-4: Handled by install.go (Install() method)
//	  Phase 1: Binary installation and user/directory creation
//	  Phase 2: Environment setup (VAULT_ADDR, VAULT_CACERT, agent directories)
//	  Phase 3: TLS certificate generation
//	  Phase 4: Configuration file generation (vault.hcl)
//
//	Phase 5-15: Handled by this function (EnableVault)
//	  Phase 5: Service startup (happens in cmd/create/secrets.go before calling EnableVault)
//	  Phase 6: Vault initialization and unseal (UnsealVault)
//	           CRITICAL: Provides root-authenticated client from vault_init.json
//	           Caches client via SetPrivilegedClient() for all subsequent phases
//	           NOTE: Agent/AppRole don't exist yet - root token is ONLY working auth method
//	  Phase 6c: IMMEDIATE audit device enablement (PhaseEnableAuditImmediately) - CRITICAL SECURITY
//	  Phase 7: Root token verification (PhasePromptAndVerRootToken)
//	  Phase 7a: API client verification (GetPrivilegedClient uses cached client)
//	  Phase 8: Health check (PhaseEnsureVaultHealthy)
//	  Phase 9a: KV v2 secrets engine (PhaseEnableKVv2)
//	  Phase 9d: Additional secrets engines - Database, PKI (PhaseEnableSecretsEngines)
//	  Phase 9e: Activity tracking enablement (PhaseEnableTracking)
//	  Phase 9b: Bootstrap secret verification (PhaseWriteBootstrapSecretAndRecheck)
//	  Phase 10a: Userpass authentication (PhaseEnableUserpass) - optional, interactive, for future runs
//	  Phase 10b: AppRole authentication (PhaseEnableAppRole) - optional, interactive, for future runs
//	  Phase 10c: Entity and alias creation (PhaseCreateEosEntity)
//	  Phase 11: Policy configuration (EnsurePolicy)
//	  Phase 12: Audit logging verification (EnableFileAudit) - redundant, audit enabled in 6c
//	  Phase 13: Multi-Factor Authentication (EnableMFAMethods) - optional, interactive
//	  Phase 14: Vault Agent service (PhaseEnableVaultAgent) - optional, interactive, for future runs
//	  Phase 15: Comprehensive hardening (ComprehensiveHardening) - optional, interactive
//
// Authentication Strategy:
//   - Initial install (this run): Root token from vault_init.json (cached in Phase 6)
//   - Subsequent runs: Agent token → AppRole → Root token (fallback)
//   - Phase 10b configures AppRole for subsequent runs
//   - Phase 14 configures Vault Agent for subsequent runs
//
// Interactive phases (10a, 10b, 13, 14, 15) prompt the user for confirmation.
func EnableVault(rc *eos_io.RuntimeContext, client *api.Client, log *zap.Logger) error {
	startTime := time.Now()
	log.Info("═══════════════════════════════════════════════════════════════")
	log.Info(" Starting Vault enablement flow (Phases 5-15)")
	log.Info("═══════════════════════════════════════════════════════════════")

	// Fall back to direct enablement
	log.Info(" [ASSESS] Checking execution environment")
	log.Info("Nomad not available, using direct enablement")

	// Clear any existing VAULT_TOKEN to ensure fresh authentication setup
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		log.Info(" [ASSESS] Found existing VAULT_TOKEN, will clear for fresh setup")
		log.Info(" [INTERVENE] Clearing existing VAULT_TOKEN environment variable")
		if err := os.Unsetenv("VAULT_TOKEN"); err != nil {
			log.Warn("Failed to unset VAULT_TOKEN", zap.Error(err))
		}
		log.Info(" [EVALUATE] VAULT_TOKEN cleared successfully")
	} else {
		log.Info(" [ASSESS] No existing VAULT_TOKEN found - proceeding with fresh setup")
	}

	// ============================================================================
	// CRITICAL P0 FIX: Run Phase 6 FIRST to get root-authenticated client
	// Then cache it for all subsequent phases (6c, 7, 8, 9, 10, 11, 12, etc.)
	//
	// Why this order matters:
	// - Phase 6 (UnsealVault) provides root-authenticated client from vault_init.json
	// - Vault Agent doesn't exist until Phase 14 (can't use agent token yet)
	// - AppRole doesn't exist until Phase 10b (can't use AppRole auth yet)
	// - Userpass doesn't exist until Phase 10a (can't use userpass yet)
	//
	// Before this fix: Phase 0 tried to authenticate before credentials existed,
	// causing 30s wait for agent token + confusing userpass prompt
	// ============================================================================
	log.Info("───────────────────────────────────────────────────────────────")
	log.Info(" [Phase 6] Initializing and unsealing Vault (provides root-authenticated client)")
	phaseStart := time.Now()
	unsealedClient, err := UnsealVault(rc)
	if err != nil {
		return logger.LogErrAndWrap(rc, "initialize and unseal vault", err)
	}

	// CRITICAL: Cache the privileged client for ALL subsequent phases
	// This prevents re-authentication attempts that would fail (Agent/AppRole not configured yet)
	log.Info(" [Phase 6] Caching authenticated client for subsequent phases",
		zap.String("vault_addr", unsealedClient.Address()),
		zap.Bool("authenticated", unsealedClient.Token() != ""))
	SetPrivilegedClient(rc, unsealedClient) // Cache for GetPrivilegedClient() calls
	SetVaultClient(rc, unsealedClient)      // Also cache as regular client

	client = unsealedClient
	log.Info(" [Phase 6] Vault initialized, unsealed, and client cached successfully",
		zap.Duration("duration", time.Since(phaseStart)))

	// CRITICAL SECURITY: Enable audit devices IMMEDIATELY after initialization
	// This ensures ALL subsequent operations are audited (policies, users, secrets, etc.)
	// HashiCorp best practice: "Enable at least one audit device immediately after initialization"
	log.Info("───────────────────────────────────────────────────────────────")
	log.Info(" [Phase 6c] Enabling audit devices IMMEDIATELY (CRITICAL)")
	phaseStart = time.Now()
	if err := PhaseEnableAuditImmediately(rc, client); err != nil {
		log.Error(" [Phase 6c] CRITICAL: Failed to enable audit devices",
			zap.Error(err),
			zap.Duration("duration", time.Since(phaseStart)))
		log.Error(" ⚠️  SECURITY IMPACT: Vault operations will NOT be audited")
		log.Error(" ⚠️  This violates compliance requirements (SOC2, PCI-DSS, HIPAA)")
		return logger.LogErrAndWrap(rc, "enable audit devices immediately", err)
	}
	log.Info(" [Phase 6c] Audit devices enabled successfully - ALL operations now audited",
		zap.Duration("duration", time.Since(phaseStart)))

	log.Info("───────────────────────────────────────────────────────────────")
	log.Info(" [Phase 7] Verifying root token and API client")
	phaseStart = time.Now()

	steps := []struct {
		name  string
		phase string
		fn    func() error
	}{
		{"verify root token", "7", func() error { return PhasePromptAndVerRootToken(rc, client) }},
		{"verify vault API client", "7a", func() error { _, err := GetPrivilegedClient(rc); return err }},
		{"verify vault healthy", "8", func() error { return PhaseEnsureVaultHealthy(rc) }},
	}

	for _, step := range steps {
		stepStart := time.Now()
		log.Info(fmt.Sprintf(" [Phase %s] Starting: %s", step.phase, step.name))
		if err := step.fn(); err != nil {
			log.Error(fmt.Sprintf(" [Phase %s] Failed: %s", step.phase, step.name),
				zap.Error(err),
				zap.Duration("duration", time.Since(stepStart)))
			return logger.LogErrAndWrap(rc, step.name, err)
		}
		log.Info(fmt.Sprintf(" [Phase %s] Completed: %s", step.phase, step.name),
			zap.Duration("duration", time.Since(stepStart)))
	}

	log.Info(" [Phase 7-8] Verification complete",
		zap.Duration("total_duration", time.Since(phaseStart)))

	// Step 9a: Enable KV v2
	log.Info("───────────────────────────────────────────────────────────────")
	log.Info(" [Phase 9a] Enabling KV v2 secrets engine")
	phaseStart = time.Now()
	if err := PhaseEnableKVv2(rc, client); err != nil {
		log.Error(" [Phase 9a] Failed to enable KV v2 secrets engine",
			zap.Error(err),
			zap.Duration("duration", time.Since(phaseStart)))
		return logger.LogErrAndWrap(rc, "enable KV v2", err)
	}
	log.Info(" [Phase 9a] KV v2 secrets engine enabled successfully",
		zap.Duration("duration", time.Since(phaseStart)))

	// Step 9b: Write bootstrap secret and verify KV v2 is working
	// CRITICAL: This MUST run immediately after Phase 9a (KV v2 enablement)
	// and BEFORE Phase 14 (Vault Agent setup) to ensure we use the root token
	// from Phase 6 before any context modifications.
	log.Info("───────────────────────────────────────────────────────────────")
	log.Info(" [Phase 9b] Writing bootstrap secret to verify KV v2")
	phaseStart = time.Now()
	if err := PhaseWriteBootstrapSecretAndRecheck(rc, client); err != nil {
		log.Error(" [Phase 9b] Failed to write bootstrap secret",
			zap.Error(err),
			zap.Duration("duration", time.Since(phaseStart)))
		return logger.LogErrAndWrap(rc, "write bootstrap secret", err)
	}
	log.Info(" [Phase 9b] Bootstrap secret written and verified successfully",
		zap.Duration("duration", time.Since(phaseStart)))

	// Step 9d: Enable additional secrets engines (database, PKI)
	log.Info("───────────────────────────────────────────────────────────────")
	log.Info(" [Phase 9d] Enabling additional secrets engines (interactive)")
	phaseStart = time.Now()
	if err := PhaseEnableSecretsEngines(rc, client); err != nil {
		log.Error(" [Phase 9d] Failed to enable additional secrets engines",
			zap.Error(err),
			zap.Duration("duration", time.Since(phaseStart)))
		return logger.LogErrAndWrap(rc, "enable additional secrets engines", err)
	}
	log.Info(" [Phase 9d] Additional secrets engines phase completed",
		zap.Duration("duration", time.Since(phaseStart)))

	// Step 9e: Enable activity tracking
	log.Info("───────────────────────────────────────────────────────────────")
	log.Info(" [Phase 9e] Enabling activity tracking")
	phaseStart = time.Now()
	if err := PhaseEnableTracking(rc, client); err != nil {
		log.Warn(" [Phase 9e] Failed to enable activity tracking (non-fatal)",
			zap.Error(err),
			zap.Duration("duration", time.Since(phaseStart)))
		log.Info("terminal prompt: Activity tracking could not be enabled automatically")
		log.Info("terminal prompt: You can enable it later with: vault write sys/internal/counters/config enabled=enable")
	} else {
		log.Info(" [Phase 9e] Activity tracking enabled successfully",
			zap.Duration("duration", time.Since(phaseStart)))
	}

	// Step 10a: interactively configure userpass auth
	log.Info("───────────────────────────────────────────────────────────────")
	log.Info(" [Phase 10a] Configuring Userpass authentication (interactive)")
	phaseStart = time.Now()

	log.Info(" [ASSESS] Checking if Userpass is already configured")
	userpassConfigured, err := IsUserpassConfigured(rc, client)
	if err != nil {
		log.Warn("Failed to check userpass status, will prompt", zap.Error(err))
		userpassConfigured = false // Default to prompting on error
	}

	if userpassConfigured {
		log.Info(" [ASSESS] Userpass authentication already configured")
		log.Info("terminal prompt: ✓ Userpass authentication already configured")
		if interaction.PromptYesNo(rc.Ctx, "  Rotate eos user password?", false) {
			password, err := crypto.PromptPassword(rc, "Enter NEW password for Eos Vault user:")
			if err != nil {
				return logger.LogErrAndWrap(rc, "prompt password", err)
			}
			log.Info(" [INTERVENE] Rotating eos user password")
			if err := UpdateUserpassPassword(rc, client, password); err != nil {
				return logger.LogErrAndWrap(rc, "rotate password", err)
			}
			log.Info(" [EVALUATE] Password rotated successfully")
			log.Info("terminal prompt: ✓ Password rotated successfully")
		} else {
			log.Info(" User chose not to rotate password")
		}
	} else {
		log.Info(" [ASSESS] Userpass not yet configured")
		if interaction.PromptYesNo(rc.Ctx, "Enable Userpass authentication?", false) {
			log.Info(" [INTERVENE] Enabling Userpass authentication")
			// empty password => will prompt internally
			if err := PhaseEnableUserpass(rc, client, log, ""); err != nil {
				return logger.LogErrAndWrap(rc, "enable Userpass", err)
			}
			log.Info(" [EVALUATE] Userpass authentication enabled")
		} else {
			log.Info(" User chose to skip Userpass authentication")
		}
	}

	log.Info(" [Phase 10a] Userpass configuration complete",
		zap.Duration("duration", time.Since(phaseStart)))

	// Step 10b: interactively configure AppRole auth
	log.Info("───────────────────────────────────────────────────────────────")
	log.Info(" [Phase 10b] Configuring AppRole authentication (interactive)")
	phaseStart = time.Now()

	log.Info(" [ASSESS] Checking if AppRole is already configured")
	approleConfigured, err := IsAppRoleConfigured(rc, client)
	if err != nil {
		log.Warn("Failed to check AppRole status, will prompt", zap.Error(err))
		approleConfigured = false // Default to prompting on error
	}

	if approleConfigured {
		log.Info(" [ASSESS] AppRole authentication already configured")
		log.Info("terminal prompt: ✓ AppRole authentication already configured")
		if interaction.PromptYesNo(rc.Ctx, "  Regenerate AppRole credentials?", false) {
			log.Info(" [INTERVENE] Regenerating AppRole credentials")
			if err := RegenerateAppRoleCredentials(rc, client); err != nil {
				return logger.LogErrAndWrap(rc, "regenerate approle credentials", err)
			}
			log.Info(" [EVALUATE] AppRole credentials regenerated successfully")
			log.Info("terminal prompt: ✓ AppRole credentials regenerated successfully")
		} else {
			log.Info(" User chose not to regenerate credentials")
		}
	} else {
		log.Info(" [ASSESS] AppRole not yet configured")
		if interaction.PromptYesNo(rc.Ctx, "Enable AppRole authentication?", false) {
			log.Info(" [INTERVENE] Enabling AppRole authentication")
			opts := shared.DefaultAppRoleOptions()
			if err := PhaseEnableAppRole(rc, client, log, opts); err != nil {
				return logger.LogErrAndWrap(rc, "enable AppRole", err)
			}
			log.Info(" [EVALUATE] AppRole authentication enabled")
		} else {
			log.Info(" User chose to skip AppRole authentication")
		}
	}

	log.Info(" [Phase 10b] AppRole configuration complete",
		zap.Duration("duration", time.Since(phaseStart)))

	// Step 10c: Create Eos entity and aliases
	log.Info("───────────────────────────────────────────────────────────────")
	log.Info(" [Phase 10c] Creating Eos entity and aliases")
	phaseStart = time.Now()
	if err := PhaseCreateEosEntity(rc); err != nil {
		log.Error(" [Phase 10c] Failed to create entity",
			zap.Error(err),
			zap.Duration("duration", time.Since(phaseStart)))
		return logger.LogErrAndWrap(rc, "create eos entity", err)
	}
	log.Info(" [Phase 10c] Entity and aliases created successfully",
		zap.Duration("duration", time.Since(phaseStart)))

	// Step 11: Write core policies
	log.Info("───────────────────────────────────────────────────────────────")
	log.Info(" [Phase 11] Writing core Vault policies")
	phaseStart = time.Now()
	if err := EnsurePolicy(rc); err != nil {
		log.Error(" [Phase 11] Failed to write policies",
			zap.Error(err),
			zap.Duration("duration", time.Since(phaseStart)))
		return logger.LogErrAndWrap(rc, "write policies", err)
	}
	log.Info(" [Phase 11] Core policies written successfully",
		zap.Duration("duration", time.Since(phaseStart)))

	// CRITICAL P0: Validate that eos-default-policy includes service secrets access
	// This prevents permission denied errors when deploying services (bionicgpt, etc.)
	log.Info(" [Phase 11.1] Validating eos-default-policy includes service secrets access")
	hasServiceSecrets, err := CheckServiceSecretsPolicy(rc)
	if err != nil {
		log.Warn(" [Phase 11.1] Could not verify service secrets policy (non-fatal)",
			zap.Error(err))
	} else if !hasServiceSecrets {
		log.Error(" [Phase 11.1] CRITICAL: eos-default-policy missing service secrets access")
		log.Error(" ⚠️  SERVICE DEPLOYMENT BLOCKED: Cannot deploy services (bionicgpt, etc.)")
		log.Error(" ⚠️  Missing path: secret/data/services/*")
		log.Error(" ⚠️  Fix with: sudo eos update vault --update-policies")
		return fmt.Errorf("eos-default-policy missing required service secrets path")
	} else {
		log.Info(" [Phase 11.1] ✓ Verified: eos-default-policy includes service secrets access")
	}

	// Step 12: Enable comprehensive audit logging
	log.Info("───────────────────────────────────────────────────────────────")
	log.Info(" [Phase 12] Enabling file-based audit logging")
	phaseStart = time.Now()
	if err := EnableFileAudit(rc, client); err != nil {
		log.Error(" [Phase 12] Failed to enable audit logging",
			zap.Error(err),
			zap.Duration("duration", time.Since(phaseStart)))
		return logger.LogErrAndWrap(rc, "enable audit backend", err)
	}
	log.Info(" [Phase 12] Audit logging enabled successfully",
		zap.Duration("duration", time.Since(phaseStart)))

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
		log.Info(" Vault Agent enablement skipped by user")
		log.Info("terminal prompt: Vault Agent not enabled. You can enable it later with manual configuration.")
	}

	// Step 15: Optional Phase 15 - Comprehensive Hardening
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
		log.Info(" [Phase 15] Hardening skipped by user")
		log.Info("terminal prompt: IMPORTANT: Run 'eos secure vault --comprehensive' before production use")
	}

	duration := time.Since(startTime)
	log.Info("═══════════════════════════════════════════════════════════════")
	log.Info(" Vault enablement process completed successfully",
		zap.Duration("total_duration", duration),
		zap.String("duration_formatted", formatDuration(duration)))
	log.Info("═══════════════════════════════════════════════════════════════")
	PrintEnableNextSteps(rc)
	return nil
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1f seconds", d.Seconds())
	}
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm %ds", minutes, seconds)
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
