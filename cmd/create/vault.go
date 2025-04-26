// cmd/create/vault.go
package create

import (
	"fmt"

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

		if err := vault.ValidateCriticalPaths(log); err != nil {
			log.Error("❌ Vault critical paths validation failed", zap.Error(err))
			return fmt.Errorf("vault critical path validation failed: %w", err)
		}

		if err := vault.StartVault(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: start service", err)
		}

		addr, err := vault.InitializeVaultOnly(log)
		if err != nil {
			return logger.LogErrAndWrap(log, "create vault: initialize", err)
		}

		log.Info("✅ Vault initialized", zap.String("VAULT_ADDR", addr))

		// 🛎️ New hint to user: guide next steps!
		fmt.Println("")
		fmt.Println("🔔 Vault has been initialized, but is not yet unsealed.")
		fmt.Println("👉 Next steps:")
		fmt.Println("   1. Run: eos inspect vault-init   (to view and save your init keys)")
		fmt.Println("   2. Run: eos enable vault         (to unseal and fully enable Vault)")
		fmt.Println("")

		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateVaultCmd)
}
