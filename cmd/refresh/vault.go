// cmd/refresh/vault.go

package refresh

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		// Check if we are root or have sudo privileges
		if err := eos_unix.EnsureEosSudoReady(rc.Ctx); err != nil {
			log.Error("❌ Required privileges not available", zap.Error(err))
			fmt.Println("👉 Please run: sudo -v && eos refresh vault --unseal")
			return fmt.Errorf("insufficient privileges: %w", err)
		}

		log.Info("🔄 Refreshing Vault service...")
		if err := eos_unix.RestartSystemdUnitWithRetry(rc.Ctx, "vault", 3, 2); err != nil {
			return fmt.Errorf("vault restart failed: %w", err)
		}

		log.Info("✅ Vault service restarted successfully")
		log.Info("ℹ️ You can check Vault health at https://127.0.0.1:8179/v1/sys/health")

		if shouldUnseal {
			log.Info("🔐 Attempting unseal because --unseal flag was provided")

			client, err := vault.GetVaultClient(rc)
			if err != nil {
				log.Error("❌ Failed to create Vault client", zap.Error(err))
				return fmt.Errorf("vault client setup failed: %w", err)
			}

			unsealed, err := vault.UnsealVaultIfNeeded(rc, client)
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
