package refresh

import (
	"os"
	"os/exec"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// VaultRefreshCmd restarts the Vault systemd service safely.
var VaultRefreshCmd = &cobra.Command{
	Use:   "vault",
	Short: "Refreshes (restarts) the Vault service",
	Long:  `Stops and restarts the Vault service cleanly through systemd.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := zap.L().Named("refresh-vault")

		if os.Geteuid() != 0 {
			log.Fatal("Root privileges are required to refresh Vault.")
		}

		log.Info("🔄 Refreshing Vault service...")

		// Stop Vault cleanly using systemd
		stopCmd := exec.Command("systemctl", "stop", "vault")
		if err := stopCmd.Run(); err != nil {
			log.Warn("⚠️ Failed to stop Vault via systemctl", zap.Error(err))
		} else {
			log.Info("✅ Vault service stopped")
		}

		time.Sleep(2 * time.Second)

		// Start Vault again
		startCmd := exec.Command("systemctl", "start", "vault")
		if err := startCmd.Run(); err != nil {
			log.Error("❌ Failed to start Vault via systemctl", zap.Error(err))
			return err
		}

		log.Info("✅ Vault service restarted successfully")
		log.Info("ℹ️ You can check Vault health at https://127.0.0.1:8179/v1/sys/health")

		return nil
	}),
}

func init() {
	RefreshCmd.AddCommand(VaultRefreshCmd)
}
