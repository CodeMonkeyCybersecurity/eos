// pkg/vault/lifecycle2_enable.go

package vault

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func CreateVaultClient() (*api.Client, error) {
	return NewClient()
}

func VaultAddress() string {
	return os.Getenv(shared.VaultAddrEnv)
}

// EnableVault now drives everything interactively.
func EnableVault(client *api.Client, log *zap.Logger) error {
	zap.L().Info("🚀 Starting Vault enablement flow")

	// Step 6b: unseal Vault if needed
	unsealedClient, err := UnsealVault()
	if err != nil {
		return logger.LogErrAndWrap("initialize and unseal vault", err)
	}
	client = unsealedClient

	// Step 7, 7a, 8: verify root token,  API client, overall vault health,
	steps := []struct {
		name string
		fn   func() error
	}{
		{"verify root token", func() error { return PhasePromptAndVerRootToken(client) }},
		{"verify vault API client", func() error { _, err := GetRootClient(); return err }},
		{"verify vault healthy", PhaseEnsureVaultHealthy},
	}
	for _, step := range steps {
		zap.L().Info(fmt.Sprintf("🔍 %s...", step.name))
		if err := step.fn(); err != nil {
			return logger.LogErrAndWrap(step.name, err)
		}
	}

	// Step 5: Enable KV v2
	if err := PhaseEnableKVv2(client); err != nil {
		return logger.LogErrAndWrap("enable KV v2", err)
	}

	// Step 6: interactively configure auth methods
	if interaction.PromptYesNo("Enable AppRole authentication?", true) {
		if err := PhaseEnableAppRole(client, log, shared.DefaultAppRoleOptions()); err != nil {
			return logger.LogErrAndWrap("enable AppRole", err)
		}
	}

	if interaction.PromptYesNo("Enable Userpass authentication?", false) {
		// empty password => will prompt internally
		if err := PhaseEnableUserpass(client, log, ""); err != nil {
			return logger.LogErrAndWrap("enable Userpass", err)
		}
	}

	// Step 7: Write core policies
	if err := EnsurePolicy(); err != nil {
		return logger.LogErrAndWrap("write policies", err)
	}

	// Step 8: Enable audit backend
	if err := EnableFileAudit(client); err != nil {
		return logger.LogErrAndWrap("enable audit backend", err)
	}

	// Step 9: interactively configure Vault Agent
	if interaction.PromptYesNo("Enable Vault Agent service?", false) {
		// Agent requires AppRole to already be enabled above.
		if err := PhaseRenderVaultAgentConfig(client); err != nil {
			return logger.LogErrAndWrap("render Vault Agent config", err)
		}
		if err := PhaseStartVaultAgentAndValidate(client); err != nil {
			return logger.LogErrAndWrap("start Vault Agent", err)
		}
	}

	// Step 10: Apply core secrets and verify readiness
	if err := PhaseWriteBootstrapSecretAndRecheck(client); err != nil {
		return logger.LogErrAndWrap("apply core secrets", err)
	}

	zap.L().Info("🎉 Vault enablement process completed successfully")
	PrintEnableNextSteps()
	return nil
}

func PrintEnableNextSteps() {
	fmt.Println("\n🔔 Vault setup is now complete!")
	fmt.Println("👉 Next steps:")
	fmt.Println("   1. Run: eos secure vault   (to finalize hardening and cleanup)")
	fmt.Println("   2. Optionally onboard new users, configure roles, or deploy agents.")
}
