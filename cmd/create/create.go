// cmd/create/create.go

package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/flags"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// CreateCmd is the root command for create operations
var CreateCmd = &cobra.Command{
	Use:     "create",
	Aliases: []string{"deploy", "install", "setup", "add", "bootstrap"},
	Short:   "Create, deploy, install resources programmes and components (e.g., processes, users, storage, application containers)",
	Long: `The create command allows you to create various resources such as processes, users, or storage, components or dependencies.
For example:
	eos deploy trivy 
	eos deploy vault
	eos deploy umami`,

	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.L()

		if flags.IsDryRun() {
			log.Info("Dry-run mode: no subcommand executed", zap.String("command", cmd.Use))
			fmt.Printf("💡 [dry-run] No subcommand was executed for '%s'\n", cmd.Use)
			return nil
		}

		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		return cmd.Help()
	}),
}
