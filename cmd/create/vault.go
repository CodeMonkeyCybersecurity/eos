// cmd/create/vault.go
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Installs Vault with TLS, systemd service, and initial configuration",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("create-vault")

		if err := vault.InstallVaultBinary(); err != nil {
			return logger.LogErrAndWrap("create vault: install binary", err)
		}
		if err := vault.PrepareEnvironment(); err != nil {
			return logger.LogErrAndWrap("create vault: prepare environment", err)
		}
		if err := vault.GenerateTLS(); err != nil {
			return logger.LogErrAndWrap("create vault: generate TLS", err)
		}
		if err := vault.WriteAndValidateConfig(); err != nil {
			return logger.LogErrAndWrap("create vault: write config", err)
		}

		if err := vault.ValidateCriticalPaths(); err != nil {
			log.Error("❌ Vault critical paths validation failed", zap.Error(err))
			return fmt.Errorf("vault critical path validation failed: %w", err)
		}

		if err := vault.StartVault(); err != nil {
			return logger.LogErrAndWrap("create vault: start service", err)
		}

		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateVaultCmd)
}
