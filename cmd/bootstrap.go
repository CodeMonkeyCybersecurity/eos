// cmd /bootstrap.go

package cmd

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/spf13/cobra"
)

// BootstrapCmd wires up system preparation for EOS.
var BootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Prepare the system for EOS installation",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("bootstrap")
		log.Info("Starting bootstrap...")

		if err := system.EnsureEosUser(true, false, log); err != nil {
			return fmt.Errorf("user setup failed: %w", err)
		}
		if err := system.SetupEosSudoers(log); err != nil {
			return fmt.Errorf("sudoers setup failed: %w", err)
		}
		if err := system.CreateEosDirectories(log); err != nil {
			return fmt.Errorf("directory setup failed: %w", err)
		}
		if err := logger.InitializeWithFallback(log); err != nil {
			return fmt.Errorf("directory setup failed: %w", err)
		}

		log.Info("Bootstrap complete. EOS is ready to install.")
		return nil
	}),
}
