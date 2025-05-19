// cmd/sync/sync.go

package sync

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var SyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync Eos components (e.g., secrets into Vault)",
	Long:  "Synchronize data or configuration from fallback or external sources.",

	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {

		zap.L().Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}
