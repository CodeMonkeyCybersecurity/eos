// cmd/create/vault.go
package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Installs Vault with TLS, systemd service, and initial configuration",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("create-vault")

		if err := vault.InstallVaultBinary(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: install binary", err)
		}
		if err := vault.PrepareEnvironment(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: prepare environment", err)
		}
		if err := vault.GenerateTLS(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: generate TLS", err)
		}
		if err := vault.WriteAndValidateConfig(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: write config", err)
		}
		if err := vault.StartVault(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: start service", err)
		}

		addr, client, err := vault.InitializeAndUnsealVault(log)
		if err != nil {
			return logger.LogErrAndWrap(log, "create vault: initialize and unseal", err)
		}

		if err := vault.ApplyCoreSecretsAndHealthCheck(client, log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: bootstrap secrets and health check", err)
		}

		log.Info("✅ Vault fully installed, initialized, unsealed, and healthy", zap.String("VAULT_ADDR", addr))
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateVaultCmd)
}
