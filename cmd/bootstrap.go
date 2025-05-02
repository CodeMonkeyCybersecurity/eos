// cmd/bootstrap.go

package cmd

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// BootstrapCmd wires system checks and preparation.
var BootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Run initial system checks and prepare EOS environment",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("bootstrap")

		log.Info("🚀 Starting EOS bootstrap process")

		// Step 1: Check eos user
		log.Info("🔍 Checking eos user setup")
		if err := system.EnsureEosUser(true, false, log); err != nil {
			log.Error("❌ Failed to ensure eos user", zap.Error(err))
			return fmt.Errorf("bootstrap failed: %w", err)
		}

		// Step 2: Check sudo permissions
		log.Info("🔍 Checking eos sudo permissions")
		ok, err := system.CheckEosSudoPermissions()
		if err != nil {
			log.Warn("⚠️ Error checking sudo permissions", zap.Error(err))
		}
		if !ok {
			log.Warn("❌ eos user missing sudoers entry or has wrong permissions")
			fmt.Println("⚠ eos user lacks required sudo permissions for systemctl.")
			fmt.Println("Would you like EOS to fix this automatically? (y/N)")

			var input string
			_, err := fmt.Scanln(&input)
			if err != nil {
				return fmt.Errorf("failed to read input: %w", err)
			}
			if input == "y" || input == "Y" {
				if err := system.FixEosSudoersFile(log); err != nil {
					return fmt.Errorf("failed to fix sudoers file: %w", err)
				}
				log.Info("✅ Fixed eos sudoers entry")
			} else {
				log.Warn("❌ User declined sudoers fix")
				fmt.Println("⚠ Please add this manually: eos ALL=(ALL) NOPASSWD: /bin/systemctl")
				return fmt.Errorf("bootstrap failed: sudoers entry missing")
			}
		} else {
			log.Info("✅ eos sudo permissions verified")
		}

		// Step 3: Verify EOS directories
		if err := system.CreateEosDirectories(log); err != nil {
			return fmt.Errorf("failed to prepare directories: %w", err)
		}

		log.Info("🎉 Bootstrap process complete")
		fmt.Println("✅ EOS bootstrap completed successfully")
		return nil
	}),
}

func init() {
	RootCmd.AddCommand(BootstrapCmd)
}
