// cmd/refresh/eos_passwd.go

package refresh

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var RefreshEosPasswdCmd = &cobra.Command{
	Use:   "eos-passwd",
	Short: "Refresh the EOS user password and update secrets safely",
	Long: `Regenerates a strong EOS password,
updates the system account password, and saves new credentials to disk.`,
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("refresh-eos-passwd")

		if !eos_unix.UserExists(shared.EosID) {
			log.Error("eos user not found — cannot refresh password")
			return fmt.Errorf("eos user does not exist")
		}

		if err := eos_unix.RepairEosSecrets(); err != nil {
			log.Error("Failed to refresh EOS credentials", zap.Error(err))
			return fmt.Errorf("refresh eos password: %w", err)
		}

		log.Info("✅ EOS password refreshed successfully")
		fmt.Println("✅ EOS password refreshed and secrets updated.")
		return nil
	}),
}

func init() {
	RefreshCmd.AddCommand(RefreshEosPasswdCmd)
}
