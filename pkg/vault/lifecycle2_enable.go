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
	zap.L().Info("🚀 [Enable] Starting Vault enablement flow")

	// --- 1. Validate conflicting options
	if opts.EnableAppRole && opts.EnableUserpass {
		zap.L().Error("❌ Cannot enable both AppRole and Userpass authentication at the same time")
		fmt.Println("\n🚫 You cannot enable both --approle and --userpass simultaneously.")
		fmt.Println("\n👉 Please re-run with either --approle or --userpass, not both.")
		return errors.New("conflicting authentication options: approle and userpass")
	}

	// --- 2. Ensure Vault server is healthy
	zap.L().Info("🔍 [Phase 7/15] Checking Vault server health...")
	if err := PhaseEnsureVaultHealthy(); err != nil {
		return logger.LogErrAndWrap("vault health check", err)
	}
	zap.L().Info("✅ Vault server is healthy")

	// --- 3. Prompt for and validate root token
	zap.L().Info("🔑 [Phase 8/15] Validating Vault root token...")
	if err := PhasePromptAndVerRootToken(client); err != nil {
		return logger.LogErrAndWrap("validate root token", err)
	}
	zap.L().Info("✅ Root token validated")

	// --- 4. Confirm Vault API client is usable
	zap.L().Info("🌐 [Phase 8A/12] Verifying Vault API client...")
	if _, err := GetPrivilegedVaultClient(); err != nil {
		return logger.LogErrAndWrap("verify vault api client", err)
	}
	zap.L().Info("✅ Vault API client is ready")

	zap.L().Info("🔒 [Phase 9/15] Enabling KV v2 secret engine...")
	if err := PhaseEnableKVv2(client); err != nil {
		return logger.LogErrAndWrap("KV v2 secret engine", err)
	}
	zap.L().Info("✅ KV v2 secrets engine and base EOS policy configured")

	// --- 5. Enable authentication method
	approleReady := false

	if opts.EnableAppRole {
		zap.L().Info("🪪 [Phase 10/15] Enabling AppRole authentication...")
		if err := PhaseEnableAppRole(client, log, opts.AppRoleOptions); err != nil {
			return logger.LogErrAndWrap("enable approle", err)
		}
		zap.L().Info("✅ AppRole authentication enabled")
		approleReady = true
	}

	if opts.EnableUserpass {
		zap.L().Info("🧑‍💻 [Phase 10/15] Enabling Userpass authentication...")
		if err := PhaseEnableUserpass(client, log, opts.Password); err != nil {
			return logger.LogErrAndWrap("enable userpass", err)
		}
		zap.L().Info("✅ Userpass authentication enabled")
	}

	// --- 6. Write core policies
	zap.L().Info("📜 [Phase 11/15] Writing core Vault policies...")
	if err := EnsurePolicy(client); err != nil {
		return logger.LogErrAndWrap("write policies", err)
	}
	zap.L().Info("✅ Vault core policies written")

	// --- 7. Enable audit backend
	zap.L().Info("🪵 [Phase 12/15] Enabling Vault audit logging...")
	if err := EnableFileAudit(client); err != nil {
		return logger.LogErrAndWrap("enable audit logging", err)
	}
	zap.L().Info("✅ Vault audit backend enabled")

	// --- 8. Render and start Vault Agent (if selected)
	if opts.EnableAgent {
		if !approleReady {
			zap.L().Error("❌ Vault Agent requires AppRole authentication to be enabled first")
			fmt.Println("\n🚫 Vault Agent cannot be enabled without AppRole authentication.")
			fmt.Println("\n👉 Please re-run with --approle or skip --agent.")
			return errors.New("vault agent requires approle")
		}

		zap.L().Info("🤖 [Phase 13/15] Rendering Vault Agent configuration...")
		if err := PhaseRenderVaultAgentConfig(client); err != nil {
			return logger.LogErrAndWrap("render vault agent config", err)
		}
		zap.L().Info("✅ Vault Agent config rendered")

		zap.L().Info("🚀 [Phase 14/15] Starting Vault Agent and validating...")
		if err := PhaseStartVaultAgentAndValidate(client); err != nil {
			return logger.LogErrAndWrap("start vault agent", err)
		}
		zap.L().Info("✅ Vault Agent running and token validated")
	}

	// --- 9. Apply core secrets and perform final health check
	zap.L().Info("🔐 [Phase 15/15] Applying core secrets and verifying readiness...")
	if err := PhaseWriteBootstrapSecretAndRecheck(client); err != nil {
		return logger.LogErrAndWrap("apply core secrets", err)
	}

	zap.L().Info("🎉 Vault enablement process completed successfully")
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
