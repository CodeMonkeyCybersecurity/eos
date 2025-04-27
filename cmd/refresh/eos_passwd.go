// cmd/refresh/passwd.go

package refresh

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var RefreshEosPasswdCmd = &cobra.Command{
	Use:   "eos-passwd",
	Short: "Refresh the EOS user password and update secrets safely",
	Long: `This command regenerates a strong EOS password,
updates the system user, and saves the credentials securely.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("refresh-eos-passwd")

		if !system.UserExists("eos") {
			log.Error("eos user not found — cannot refresh password")
			return fmt.Errorf("eos user does not exist")
		}

		if err := system.RepairEosSecrets(log); err != nil {
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
