// cmd/create/vault.go
package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Installs Vault with TLS and systemd service (no init/unseal)",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("create-vault")

		// 1️⃣ Install Vault
		if err := vault.PhaseInstallVault(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: install", err)
		}

		// 2️⃣ Prepare environment
		if err := system.EnsureEosUser(true, false, log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: ensure eos user", err)
		}
		if err := vault.EnsureVaultDirs(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: ensure vault dirs", err)
		}
		if err := vault.PrepareVaultAgentEnvironment(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: prepare agent env", err)
		}

		// 3️⃣ Generate TLS
		if err := vault.GenerateVaultTLSCert(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: generate TLS certs", err)
		}
		if err := vault.TrustVaultCA(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: trust CA cert", err)
		}

		// 4️⃣ Write and Validate Config
		if err := vault.PhaseEnsureVaultConfigExists(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: ensure config", err)
		}
		if err := vault.PhasePatchVaultConfigIfNeeded(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: patch config", err)
		}
		if err := vault.ValidateVaultConfig(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: validate config", err)
		}

		// 5️⃣ Start vault.service
		if err := vault.StartVaultService(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: start service", err)
		}

		// 6️⃣ Initialize and Unseal
		addr, err := vault.EnsureVaultEnv(log)
		if err != nil {
			return logger.LogErrAndWrap(log, "create vault: resolve VAULT_ADDR", err)
		}
		client, err := vault.NewClient(log)
		if err != nil {
			return logger.LogErrAndWrap(log, "create vault: new client", err)
		}
		client, err = vault.PhaseInitAndUnsealVault(client, log)
		if err != nil {
			return logger.LogErrAndWrap(log, "create vault: init/unseal", err)
		}

		// 7️⃣ Apply core secrets and health-check
		if err := vault.PhaseApplyCoreSecrets(client, "secret/config", map[string]string{"example_key": "example_value"}, log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: apply core secrets", err)
		}
		if _, err := vault.CheckVaultHealth(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: health check", err)
		}

		log.Info("✅ Vault is fully installed, initialized, unsealed, and ready for use!", zap.String("VAULT_ADDR", addr))
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateVaultCmd)
}
