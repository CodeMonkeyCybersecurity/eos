// pkg/vault/lifecycle2_enable.go

package vault

import (
	"fmt"
	"os"

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

// EnableVault now drives everything interactively.
func EnableVault(rc *eos_io.RuntimeContext, client *api.Client, log *zap.Logger) error {
	log.Info("🚀 Starting Vault enablement flow")
	
	// Clear any existing VAULT_TOKEN to ensure fresh authentication setup
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		log.Info("🧹 Clearing existing VAULT_TOKEN environment variable for fresh setup", 
			zap.String("old_token_prefix", token[:12]+"..."))
		os.Unsetenv("VAULT_TOKEN")
		log.Info("✅ VAULT_TOKEN cleared successfully")
	} else {
		log.Info("✅ No existing VAULT_TOKEN found - proceeding with fresh setup")
	}

	log.Info("🔓 Starting Vault initialization and unseal process")
	unsealedClient, err := UnsealVault(rc)
	if err != nil {
		return logger.LogErrAndWrap(rc, "initialize and unseal vault", err)
	}
	client = unsealedClient
	log.Info("✅ Vault client initialized and unsealed successfully")

	steps := []struct {
		name string
		fn   func() error
	}{
		{"verify root token", func() error { return PhasePromptAndVerRootToken(rc, client) }},
		{"verify vault API client", func() error { _, err := GetRootClient(rc); return err }},
		{"verify vault healthy", func() error {
			// TODO: Implement a real health check if required.
			otelzap.Ctx(rc.Ctx).Info("Vault health check not implemented yet — skipping")
			return nil
		}},
	}
	for _, step := range steps {
		otelzap.Ctx(rc.Ctx).Info(fmt.Sprintf("🔍 %s...", step.name))
		if err := step.fn(); err != nil {
			return logger.LogErrAndWrap(rc, step.name, err)
		}
	}

	// Step 9a: Enable KV v2
	log.Info("🗂️ Enabling KV v2 secrets engine")
	if err := PhaseEnableKVv2(rc, client); err != nil {
		log.Error("❌ Failed to enable KV v2 secrets engine", zap.Error(err))
		return logger.LogErrAndWrap(rc, "enable KV v2", err)
	}
	log.Info("✅ KV v2 secrets engine enabled successfully")

	// Step 10a: interactively configure userpass auth
	if interaction.PromptYesNo(rc.Ctx, "Enable Userpass authentication?", false) {
		// empty password => will prompt internally
		if err := PhaseEnableUserpass(rc, client, log, ""); err != nil {
			return logger.LogErrAndWrap(rc, "enable Userpass", err)
		}
	}

	// Step 10b: interactively configure AppRole auth
	if interaction.PromptYesNo(rc.Ctx, "Enable AppRole authentication?", false) {
		opts := shared.DefaultAppRoleOptions()
		if err := PhaseEnableAppRole(rc, client, log, opts); err != nil {
			return logger.LogErrAndWrap(rc, "enable AppRole", err)
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
		log.Info("✅ MFA configuration completed")
	} else {
		log.Warn("⚠️ MFA was not enabled - this reduces security")
	}

	// Step 14: Vault Agent comprehensive enablement
	if interaction.PromptYesNo(rc.Ctx, "Enable Vault Agent service?", true) {
		log.Info("🤖 Starting Vault Agent enablement")
		config := DefaultVaultAgentConfig()
		if err := PhaseEnableVaultAgent(rc, client, config); err != nil {
			return logger.LogErrAndWrap(rc, "enable Vault Agent", err)
		}
		log.Info("✅ Vault Agent enabled successfully")
		fmt.Println("✅ Vault Agent is now running and configured for automatic authentication")
	} else {
		log.Info("⏭️ Vault Agent enablement skipped by user")
		fmt.Println("ℹ️ Vault Agent not enabled. You can enable it later with manual configuration.")
	}

	// Step 15: Apply core secrets and verify readiness
	if err := PhaseWriteBootstrapSecretAndRecheck(rc, client); err != nil {
		return logger.LogErrAndWrap(rc, "apply core secrets", err)
	}

	// Step 16: Optional root token revocation
	if interaction.PromptYesNo(rc.Ctx, "Revoke root token for enhanced security? (Ensure alternative auth methods work first)", false) {
		if err := revokeRootTokenSafely(rc, client); err != nil {
			log.Warn("⚠️ Root token revocation failed", zap.Error(err))
			fmt.Println("⚠️ Root token revocation failed. You can revoke it later using 'eos secure vault --comprehensive'")
		} else {
			log.Info("✅ Root token revoked successfully")
			fmt.Println("✅ Root token has been revoked. Use alternative authentication methods for future access.")
		}
	} else {
		log.Info("📝 Root token kept active - remember to revoke it after setting up alternative auth")
	}

	log.Info("🎉 Vault enablement process completed successfully")
	PrintEnableNextSteps()
	return nil
}

func PrintEnableNextSteps() {
	fmt.Println("\n🔔 Vault setup is now complete!")
	fmt.Println("👉 Next steps:")
	fmt.Println("   1. Run: eos secure vault   (to finalize hardening and cleanup)")
	fmt.Println("   2. Test Vault Agent: eos read vault agent")
	fmt.Println("   3. Optionally onboard new users, configure roles, or deploy additional services.")
}
