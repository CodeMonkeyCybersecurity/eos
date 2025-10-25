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
//	  Phase 9f: Consul secrets engine enablement (PhaseEnableConsulSecretsEngine) - NEW in Phase 1
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
		log.Error("   SECURITY IMPACT: Vault operations will NOT be audited")
		log.Error("   This violates compliance requirements (SOC2, PCI-DSS, HIPAA)")
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

	// Step 9f: Enable Consul secrets engine (Phase 1 - NEW)
	log.Info("───────────────────────────────────────────────────────────────")
	log.Info(" [Phase 9f] Enabling Consul secrets engine for dynamic token generation")
	phaseStart = time.Now()
	if err := PhaseEnableConsulSecretsEngine(rc, client); err != nil {
		log.Warn(" [Phase 9f] Failed to enable Consul secrets engine (non-fatal)",
			zap.Error(err),
			zap.Duration("duration", time.Since(phaseStart)))
		log.Info("terminal prompt: Consul secrets engine could not be enabled automatically")
		log.Info("terminal prompt: You can enable it later with: eos update vault --enable-consul-secrets")
	} else {
		log.Info(" [Phase 9f] Consul secrets engine enabled successfully",
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
		log.Error("   SERVICE DEPLOYMENT BLOCKED: Cannot deploy services (bionicgpt, etc.)")
		log.Error("   Missing path: secret/data/services/*")
		log.Error("   Fix with: sudo eos update vault --policies")
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
	log.Info("───────────────────────────────────────────────────────────────")
	log.Info(" [Phase 13] Configuring Multi-Factor Authentication (interactive)")
	phaseStart = time.Now()

	if interaction.PromptYesNo(rc.Ctx, "Enable Multi-Factor Authentication (MFA)?", true) {

		// STEP 1: Create MFA methods (no enforcement yet)
		log.Info(" [INTERVENE] Creating MFA methods")
		mfaConfig := DefaultMFAConfig()
		if err := CreateMFAMethodsOnly(rc, client, mfaConfig); err != nil {
			log.Error(" [Phase 13] Failed to create MFA methods",
				zap.Error(err),
				zap.Duration("duration", time.Since(phaseStart)))
			return logger.LogErrAndWrap(rc, "create MFA methods", err)
		}
		log.Info(" [EVALUATE] MFA methods created successfully")

		// STEP 2: Setup and verify TOTP (before enforcement)
		log.Info("")
		log.Info(" [INTERVENE] Setting up TOTP for eos user")
		log.Info("")
		log.Info("IMPORTANT: You enabled MFA, so the 'eos' user needs a TOTP secret.")
		log.Info("We'll set this up now and verify it works BEFORE enforcing MFA.")
		log.Info("")

		// Check if userpass is configured (eos user exists)
		userpassConfigured, err := IsUserpassConfigured(rc, client)
		if err != nil {
			log.Warn("Could not check if userpass is configured", zap.Error(err))
			userpassConfigured = false
		}

		if userpassConfigured {
			// Verify all MFA prerequisites before attempting TOTP setup
			// CRITICAL P1: This early verification provides fail-fast behavior and
			// prevents generating TOTP secrets if prerequisites are missing.
			log.Info(" [ASSESS] Verifying MFA prerequisites before setup")
			log.Info("   Prerequisites being checked:")
			log.Info("     1. Userpass user exists")
			log.Info("     2. Entity exists (by name or alias)")
			log.Info("     3. Entity alias exists for userpass mount")
			log.Info("     4. Bootstrap password secret exists (Phase 10a completion)")
			log.Info("")

			if err := VerifyMFAPrerequisites(rc, client, "eos"); err != nil {
				log.Error(" [Phase 13] MFA prerequisites check failed",
					zap.Error(err))
				log.Error("")
				log.Error("  MFA setup cannot proceed because prerequisites are missing.")
				log.Error("  Run 'sudo eos debug vault --identities' for detailed diagnostics.")
				log.Error("")
				return logger.LogErrAndWrap(rc, "verify MFA prerequisites", err)
			}

			log.Info("")
			log.Info(" [EVALUATE] All MFA prerequisites verified successfully")
			log.Info("   ✓ Userpass user exists")
			log.Info("   ✓ Entity exists and is properly configured")
			log.Info("   ✓ Bootstrap password available for TOTP setup")
			log.Info("")

			// Set up TOTP for the eos user
			if err := SetupUserTOTP(rc, client, "eos"); err != nil {
				log.Error(" [Phase 13] CRITICAL: Failed to set up TOTP for eos user",
					zap.Error(err),
					zap.Duration("duration", time.Since(phaseStart)))
				log.Error("")
				log.Error("  TOTP setup failed, but MFA is NOT yet enforced.")
				log.Error("  You can retry safely without being locked out.")
				log.Error("")
				log.Error("To retry: Run 'eos update vault --setup-mfa-user eos'")
				log.Error("")
				return logger.LogErrAndWrap(rc, "setup TOTP for eos user", err)
			}
			log.Info(" [EVALUATE] TOTP setup and verification succeeded")

			// STEP 3: ONLY NOW enforce MFA (after verification succeeded)
			log.Info("")
			log.Info(" [INTERVENE] Enforcing MFA policy")
			log.Info("TOTP has been verified to work, now enforcing MFA for all logins...")
			log.Info("")

			if err := EnforceMFAPolicyOnly(rc, client, mfaConfig); err != nil {
				log.Error(" [Phase 13] Failed to enforce MFA policy",
					zap.Error(err),
					zap.Duration("duration", time.Since(phaseStart)))
				log.Error("")
				log.Error("  TOTP is configured and working, but enforcement failed.")
				log.Error("  Users can still login with just passwords (MFA not required yet).")
				log.Error("")
				log.Error("To retry enforcement: Run 'eos update vault --enforce-mfa'")
				log.Error("")
				return logger.LogErrAndWrap(rc, "enforce MFA policy", err)
			}
			log.Info(" [EVALUATE] MFA enforcement active")

		} else {
			log.Warn("")
			log.Warn("  Userpass authentication is not configured yet.")
			log.Warn("  Skipping TOTP setup and enforcement.")
			log.Warn("")
			log.Warn("If you enable userpass later, you MUST configure TOTP:")
			log.Warn("  eos update vault --setup-mfa-user <username>")
			log.Warn("")
		}

		log.Info(" [Phase 13] MFA configuration completed",
			zap.Duration("duration", time.Since(phaseStart)))
	} else {
		log.Warn(" [Phase 13] MFA was not enabled - this reduces security",
			zap.Duration("duration", time.Since(phaseStart)))
		log.Warn("")
		log.Warn("  SECURITY WARNING: MFA provides critical protection against:")
		log.Warn("   • Stolen passwords")
		log.Warn("   • Brute force attacks")
		log.Warn("   • Credential stuffing")
		log.Warn("")
		log.Warn("You can enable MFA later with: eos update vault --enable-mfa")
		log.Warn("")
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

		// CRITICAL P1 FIX: Hardening requires privileged client (root token)
		// Phase 14 set Agent token on client, but hardening operations like
		// enabling audit logging require sudo capability (only root has).
		log.Info(" [Phase 15] Getting privileged client for hardening operations")
		privilegedClient, err := GetPrivilegedClient(rc)
		if err != nil {
			log.Error(" [Phase 15] Failed to get privileged client for hardening",
				zap.Error(err),
				zap.String("remediation", "Some hardening steps (audit logging, rate limiting) require root token"))
			log.Warn("Comprehensive hardening failed (non-fatal)", zap.Error(err))
			log.Info("terminal prompt: Some hardening steps failed. You can retry with: eos secure vault --comprehensive")
		} else {
			// Use privileged client for hardening
			if err := ComprehensiveHardening(rc, privilegedClient, hardeningConfig); err != nil {
				log.Warn("Comprehensive hardening failed (non-fatal)", zap.Error(err))
				log.Info("terminal prompt: Some hardening steps failed. You can retry with: eos secure vault --comprehensive")
			} else {
				log.Info(" [Phase 15] Comprehensive hardening completed successfully")
				log.Info("terminal prompt: Vault has been hardened for production use")
			}
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
