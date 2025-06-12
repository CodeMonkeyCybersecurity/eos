// cmd/refresh/eos_passwd.go

package refresh

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var RefreshEosPasswdCmd = &cobra.Command{
	Use:   "eos-passwd",
	Short: "Refresh the Eos user password and update secrets safely",
	Long: `Regenerates a strong Eos password,
updates the system account password, and saves new credentials to disk.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		if !eos_unix.UserExists(shared.EosID) {
			log.Error("eos user not found — cannot refresh password")
			return fmt.Errorf("eos user does not exist")
		}

		if err := eos_unix.RepairEosSecrets(rc.Ctx); err != nil {
			log.Error("Failed to refresh Eos credentials", zap.Error(err))
			return fmt.Errorf("refresh eos password: %w", err)
		}

		log.Info("✅ Eos password refreshed successfully")
		fmt.Println("✅ Eos password refreshed and secrets updated.")
		return nil
	}),
}

func init() {
	RefreshCmd.AddCommand(RefreshEosPasswdCmd)
}
