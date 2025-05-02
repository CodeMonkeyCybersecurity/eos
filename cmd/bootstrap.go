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
	Short: "Run initial system checks and prepare EOS environment",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("bootstrap")
		log.Info("🚀 Starting EOS bootstrap process")

		// Pre-check: can we sudo?
		if err := system.CheckNonInteractiveSudo(); err != nil {
			log.Warn("❌ sudo check failed", zap.Error(err))

			if system.IsInteractive() {
				fmt.Println("⚠️ It looks like your sudo session has expired or sudoers are missing.")
				fmt.Println("To fix this manually, run:")
				fmt.Println()
				fmt.Println("  sudo -v")
				fmt.Println("  eos bootstrap --yes")
				fmt.Println()
				return fmt.Errorf("bootstrap aborted: sudo session invalid or sudoers missing")
			}

			return fmt.Errorf("bootstrap failed: sudo check: %w", err)
		}

		if err := system.EnsureEosSudoReady(log); err != nil {
			return err
		}

		// Step 1: Check eos sudoers BEFORE switching to eos user
		ok, err := system.CheckEosSudoPermissions()
		if err != nil {
			log.Warn("⚠️ Error checking sudo permissions", zap.Error(err))
		}
		if !ok {
			// Prompt or auto-approve before privilege switch
			fixOk, promptErr := system.PromptWithFallback("⚠ eos user lacks required sudo permissions for systemctl. Fix automatically? (y/N): ")
			if promptErr != nil {
				return fmt.Errorf("bootstrap aborted: %w", promptErr)
			}
			if !fixOk {
				log.Error("❌ eos sudoers entry is missing")
				fmt.Println("To fix this manually, run:")
				fmt.Println()
				fmt.Println(`  echo "eos ALL=(ALL) NOPASSWD: /bin/systemctl" | sudo tee /etc/sudoers.d/eos`)
				fmt.Println(`  sudo chmod 440 /etc/sudoers.d/eos`)
				fmt.Println(`  sudo visudo -c`)
				fmt.Println()
				fmt.Println("Then rerun:")
				fmt.Println("  eos bootstrap --yes")
				return fmt.Errorf("bootstrap aborted: sudoers entry missing")
			}
			if err := system.FixEosSudoersFile(log); err != nil {
				return fmt.Errorf("failed to fix sudoers file: %w", err)
			}
		}

		// Switch to eos user AFTER fixes are decided
		if err := eosio.RequireEosUserOrReexec(log); err != nil {
			return fmt.Errorf("bootstrap privilege escalation failed: %w", err)
		}

		// Step 2: Ensure eos user exists
		log.Info("🔍 Checking eos user setup")
		if err := system.EnsureEosUser(true, false, log); err != nil {
			return fmt.Errorf("bootstrap failed: %w", err)
		}

		// Step 3: Prepare EOS directories
		if err := system.CreateEosDirectories(log); err != nil {
			return fmt.Errorf("failed to prepare directories: %w", err)
		}

		log.Info("🎉 Bootstrap process complete")
		fmt.Println("✅ EOS bootstrap completed successfully")
		return nil
	}),
}
