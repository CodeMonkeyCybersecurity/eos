package vault

import (
	"fmt"
	"os"

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

func EnableVault(client *api.Client, log *zap.Logger, opts EnableOptions) error {
	zap.L().Info("🚀 Starting Vault enablement flow")

	// Step 0: Initialize and unseal Vault if needed
	unsealedClient, err := UnsealVault()
	if err != nil {
		return logger.LogErrAndWrap("initialize and unseal vault", err)
	}
	client = unsealedClient

	// Step 1: Validate options
	if opts.EnableAppRole && opts.EnableUserpass {
		return fmt.Errorf("cannot enable both AppRole and Userpass authentication at the same time")
	}

	// Step 2–4: Check health, root token, API client
	steps := []struct {
		name string
		fn   func() error
	}{
		{"check vault health", PhaseEnsureVaultHealthy},
		{"validate root token", func() error { return PhasePromptAndVerRootToken(client) }},
		{"verify vault API client", func() error { _, err := GetPrivilegedVaultClient(); return err }},
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

	// Step 6: Enable authentication methods
	if err := enableAuthMethods(client, log, opts); err != nil {
		return err
	}

	// Step 7: Write core policies
	if err := EnsurePolicy(client); err != nil {
		return logger.LogErrAndWrap("write policies", err)
	}

	// Step 8: Enable audit backend
	if err := EnableFileAudit(client); err != nil {
		return logger.LogErrAndWrap("enable audit backend", err)
	}

	// Step 9: Optional agent setup
	if opts.EnableAgent {
		if err := setupVaultAgent(client, opts); err != nil {
			return err
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

func enableAuthMethods(client *api.Client, log *zap.Logger, opts EnableOptions) error {
	if opts.EnableAppRole {
		if err := PhaseEnableAppRole(client, log, opts.AppRoleOptions); err != nil {
			return logger.LogErrAndWrap("enable AppRole", err)
		}
	}
	if opts.EnableUserpass {
		if err := PhaseEnableUserpass(client, log, opts.Password); err != nil {
			return logger.LogErrAndWrap("enable Userpass", err)
		}
	}
	return nil
}

func setupVaultAgent(client *api.Client, opts EnableOptions) error {
	if !opts.EnableAppRole {
		return fmt.Errorf("vault Agent requires AppRole authentication")
	}
	if err := PhaseRenderVaultAgentConfig(client); err != nil {
		return logger.LogErrAndWrap("render Vault Agent config", err)
	}
	if err := PhaseStartVaultAgentAndValidate(client); err != nil {
		return logger.LogErrAndWrap("start Vault Agent", err)
	}
	return nil
}

func PrintEnableNextSteps() {
	fmt.Println("\n🔔 Vault setup is now complete!")
	fmt.Println("👉 Next steps:")
	fmt.Println("   1. Run: eos secure vault   (to finalize hardening and cleanup)")
	fmt.Println("   2. Optionally onboard new users, configure roles, or deploy agents.")
}
