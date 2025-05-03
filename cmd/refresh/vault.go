// cmd/refresh/vault.go

package refresh

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func init() {
	VaultRefreshCmd.Flags().BoolVar(&shouldUnseal, "unseal", false, "Unseal Vault after restarting")
	RefreshCmd.AddCommand(VaultRefreshCmd)
}

var shouldUnseal bool

// VaultRefreshCmd restarts the Vault systemd service and optionally unseals it if --unseal is provided.
var VaultRefreshCmd = &cobra.Command{
	Use:   "vault",
	Short: "Refreshes (restarts) the Vault service",
	Long:  `Stops and restarts the Vault service cleanly through systemd.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("refresh-vault")

		// Check if we are root or have sudo privileges
		if err := system.EnsureEosSudoReady(); err != nil {
			log.Error("❌ Required privileges not available", zap.Error(err))
			fmt.Println("👉 Please run: sudo -v && eos refresh vault --unseal")
			return fmt.Errorf("insufficient privileges: %w", err)
		}

		log.Info("🔄 Refreshing Vault service...")
		if err := system.RestartSystemdUnitWithRetry("vault", 3, 2); err != nil {
			return fmt.Errorf("vault restart failed: %w", err)
		}

		log.Info("✅ Vault service restarted successfully")
		log.Info("ℹ️ You can check Vault health at https://127.0.0.1:8179/v1/sys/health")

		if shouldUnseal {
			log.Info("🔐 Attempting unseal because --unseal flag was provided")

			client, err := vault.EnsureVaultClient()
			if err != nil {
				log.Error("❌ Failed to create Vault client", zap.Error(err))
				return fmt.Errorf("vault client setup failed: %w", err)
			}

			unsealed, err := vault.UnsealVaultIfNeeded(client)
			if err != nil {
				return fmt.Errorf("vault unseal failed: %w", err)
			}

			if unsealed {
				log.Info("✅ Vault is now unsealed")
			} else {
				log.Warn("⚠️ Vault was already unsealed")
			}
		}

		return nil
	}),
}
