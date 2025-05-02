// cmd/bootstrap.go

package cmd

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func init() {
	RootCmd.AddCommand(BootstrapCmd)
	BootstrapCmd.Flags().BoolVarP(&shared.AutoApprove, "yes", "y", false, "Automatically apply fixes without prompting")

}

// BootstrapCmd wires system checks and preparation.
var BootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Run initial system checks and prepare EOS environment (requires root/sudo)",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("bootstrap")
		log.Info("🚀 Starting EOS bootstrap process")

		// Check and elevate to root
		if err := system.RequireRootInteractive(); err != nil {
			return fmt.Errorf("bootstrap requires root: %w", err)
		}

		// Step 1: Ensure eos user
		log.Info("🔍 Ensuring eos user")
		if err := system.EnsureEosUser(true, false, log); err != nil {
			return fmt.Errorf("failed to ensure eos user: %w", err)
		}

		// Step 2: Ensure sudoers file
		ok, err := system.CheckEosSudoPermissions()
		if err != nil {
			log.Warn("⚠️ Error checking eos sudo permissions", zap.Error(err))
		}
		if !ok {
			log.Info("⚙️ Setting up eos sudoers entry")
			if err := system.FixEosSudoersFile(log); err != nil {
				return fmt.Errorf("failed to fix sudoers file: %w", err)
			}
		}

		// Step 3: Create directories
		if err := system.CreateEosDirectories(log); err != nil {
			return fmt.Errorf("failed to create eos directories: %w", err)
		}

		log.Info("🎉 Bootstrap complete")
		fmt.Println("✅ EOS bootstrap completed successfully")
		return nil
	}),
}
