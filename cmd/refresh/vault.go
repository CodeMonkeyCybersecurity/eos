// cmd/refresh/vault.go

package refresh

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
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
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := zap.L().Named("refresh-vault")

		if !utils.IsPrivilegedUser(log) {
			return fmt.Errorf("vault refresh requires 'eos' or root privileges")
		}

		log.Info("🔄 Refreshing Vault service...")
		if err := system.RestartSystemdUnitWithRetry(log, "vault", 3, 2); err != nil {
			return fmt.Errorf("vault restart failed: %w", err)
		}

		log.Info("✅ Vault service restarted successfully")
		log.Info("ℹ️ You can check Vault health at https://127.0.0.1:8179/v1/sys/health")

		if shouldUnseal {
			log.Info("🔐 Attempting unseal because --unseal flag was provided")

			client, err := vault.EnsureVaultClient(log)
			if err != nil {
				log.Error("❌ Failed to create Vault client", zap.Error(err))
				return fmt.Errorf("vault client setup failed: %w", err)
			}

			unsealed, err := vault.UnsealVaultIfNeeded(client, log)
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
