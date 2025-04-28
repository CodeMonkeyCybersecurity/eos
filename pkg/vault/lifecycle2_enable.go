// pkg/vault/lifecycle2_enable.go
package vault

import (
	"errors"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// EOS Vault Enablement Lifecycle
//
// Phases:
// 7.  Check Vault Health
// 8.  Validate Root Token
// 9.  Enable Auth Methods and Apply Policies
// 10. Enable AppRole OR Userpass (Exclusive)
// 11. Render Vault Agent Config
// 12. Start Vault Agent and Validate
//--------------------------------------------------------------------

func EnableVault(client *api.Client, log *zap.Logger, opts EnableOptions) error {
	log.Info("🚀 [Enable] Starting Vault enablement flow")

	// --- 1. Validate conflicting options
	if opts.EnableAppRole && opts.EnableUserpass {
		log.Error("❌ Cannot enable both AppRole and Userpass authentication at the same time")
		fmt.Println("\n🚫 You cannot enable both --approle and --userpass simultaneously.")
		fmt.Println("\n👉 Please re-run with either --approle or --userpass, not both.")
		return errors.New("conflicting authentication options: approle and userpass")
	}

	// --- 2. Ensure Vault server is healthy
	log.Info("🔍 [Phase 7/15] Checking Vault server health...")
	if err := PhaseEnsureVaultHealthy(log); err != nil {
		return logger.LogErrAndWrap(log, "vault health check", err)
	}
	log.Info("✅ Vault server is healthy")

	// --- 3. Prompt for and validate root token
	log.Info("🔑 [Phase 8/15] Validating Vault root token...")
	if err := PhasePromptAndVerRootToken(client, log); err != nil {
		return logger.LogErrAndWrap(log, "validate root token", err)
	}
	log.Info("✅ Root token validated")

	// --- 4. Confirm Vault API client is usable
	log.Info("🌐 [Phase 8A/12] Verifying Vault API client...")
	if _, err := GetPrivilegedVaultClient(log); err != nil {
		return logger.LogErrAndWrap(log, "verify vault api client", err)
	}
	log.Info("✅ Vault API client is ready")

	log.Info("🔒 [Phase 9/15] Enabling KV v2 secret engine...")
	if err := PhaseEnableKVv2(client, log); err != nil {
		return logger.LogErrAndWrap(log, "KV v2 secret engine", err)
	}
	log.Info("✅ KV v2 secrets engine and base EOS policy configured")

	// --- 5. Enable authentication method
	approleReady := false

	if opts.EnableAppRole {
		log.Info("🪪 [Phase 10/15] Enabling AppRole authentication...")
		if err := PhaseEnableAppRole(client, log, opts.AppRoleOptions); err != nil {
			return logger.LogErrAndWrap(log, "enable approle", err)
		}
		log.Info("✅ AppRole authentication enabled")
		approleReady = true
	}

	if opts.EnableUserpass {
		log.Info("🧑‍💻 [Phase 10/15] Enabling Userpass authentication...")
		if err := PhaseEnableUserpass(client, log, opts.Password); err != nil {
			return logger.LogErrAndWrap(log, "enable userpass", err)
		}
		log.Info("✅ Userpass authentication enabled")
	}

	// --- 6. Write core policies
	log.Info("📜 [Phase 11/15] Writing core Vault policies...")
	if err := EnsurePolicy(client, log); err != nil {
		return logger.LogErrAndWrap(log, "write policies", err)
	}
	log.Info("✅ Vault core policies written")

	// --- 7. Enable audit backend
	log.Info("🪵 [Phase 12/15] Enabling Vault audit logging...")
	if err := EnableFileAudit(client, log); err != nil {
		return logger.LogErrAndWrap(log, "enable audit logging", err)
	}
	log.Info("✅ Vault audit backend enabled")

	// --- 8. Render and start Vault Agent (if selected)
	if opts.EnableAgent {
		if !approleReady {
			log.Error("❌ Vault Agent requires AppRole authentication to be enabled first")
			fmt.Println("\n🚫 Vault Agent cannot be enabled without AppRole authentication.")
			fmt.Println("\n👉 Please re-run with --approle or skip --agent.")
			return errors.New("vault agent requires approle")
		}

		log.Info("🤖 [Phase 13/15] Rendering Vault Agent configuration...")
		if err := PhaseRenderVaultAgentConfig(client, log); err != nil {
			return logger.LogErrAndWrap(log, "render vault agent config", err)
		}
		log.Info("✅ Vault Agent config rendered")

		log.Info("🚀 [Phase 14/15] Starting Vault Agent and validating...")
		if err := PhaseStartVaultAgentAndValidate(client, log); err != nil {
			return logger.LogErrAndWrap(log, "start vault agent", err)
		}
		log.Info("✅ Vault Agent running and token validated")
	}

	// --- 9. Apply core secrets and perform final health check
	log.Info("🔐 [Phase 15/15] Applying core secrets and verifying readiness...")
	if err := PhaseWriteBootstrapSecretAndRecheck(client, log); err != nil {
		return logger.LogErrAndWrap(log, "apply core secrets", err)
	}

	log.Info("🎉 Vault enablement process completed successfully")
	PrintEnableNextSteps()
	return nil
}

// PrintEnableNextSteps prints final user instructions after enabling Vault.
func PrintEnableNextSteps() {
	fmt.Println("")
	fmt.Println("🔔 Vault setup is now complete!")
	fmt.Println("👉 Next steps:")
	fmt.Println("   1. Run: eos secure vault   (to finalize hardening and cleanup)")
	fmt.Println("   2. Optionally onboard new users, configure roles, or deploy agents.")
	fmt.Println("")
}
