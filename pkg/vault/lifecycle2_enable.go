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

	unsealedClient, err := UnsealVault(rc)
	if err != nil {
		return logger.LogErrAndWrap(rc, "initialize and unseal vault", err)
	}
	client = unsealedClient

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
	if err := PhaseEnableKVv2(rc, client); err != nil {
		return logger.LogErrAndWrap(rc, "enable KV v2", err)
	}

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

	// Step 12: Enable audit backend
	if err := EnableFileAudit(rc, client); err != nil {
		return logger.LogErrAndWrap(rc, "enable audit backend", err)
	}

	// // Step 9: interactively configure Vault Agent
	// if interaction.PromptYesNo("Enable Vault Agent service?", false) {
	// 	// Agent requires AppRole to already be enabled above.
	// 	if err := PhaseRenderVaultAgentConfig(client); err != nil {
	// 		return logger.LogErrAndWrap("render Vault Agent config", err)
	// 	}
	// 	if err := PhaseStartVaultAgentAndValidate(client); err != nil {
	// 		return logger.LogErrAndWrap("start Vault Agent", err)
	// 	}
	// }

	// Step 13-14: placeholder for Vault Agent
	if interaction.PromptYesNo(rc.Ctx, "Enable Vault Agent service?", false) {
		otelzap.Ctx(rc.Ctx).Warn("⚠ Vault Agent enablement is not yet implemented — skipping this step")
		fmt.Println("⚠ Vault Agent logic is not yet ready. Please skip this step or follow manual setup instructions.")
	}

	// Step 10: Apply core secrets and verify readiness
	if err := PhaseWriteBootstrapSecretAndRecheck(rc, client); err != nil {
		return logger.LogErrAndWrap(rc, "apply core secrets", err)
	}

	log.Info("🎉 Vault enablement process completed successfully")
	PrintEnableNextSteps()
	return nil
}

func PrintEnableNextSteps() {
	fmt.Println("\n🔔 Vault setup is now complete!")
	fmt.Println("👉 Next steps:")
	fmt.Println("   1. Run: eos secure vault   (to finalize hardening and cleanup)")
	fmt.Println("   2. Optionally onboard new users, configure roles, or deploy agents.")
}
