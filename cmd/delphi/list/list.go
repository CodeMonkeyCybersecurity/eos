// cmd/delphi/list/list.go

package list

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap" // Make sure zap is imported for structured logging
)

// ListCmd represents the 'list' command for Delphi (Wazuh) data.
var ListCmd = &cobra.Command{
	Use:   "list", // Changed to "list"
	Short: "List Delphi (Wazuh) resources",
	Long: `The 'list' command provides functionality to enumerate various resources within your Delphi (Wazuh) instance.

Use this command to retrieve lists of agents, rules, groups, and other relevant data.

Subcommands are required to specify which type of resource to list.`,
	Aliases: []string{"ls", "show"}, // Common aliases for 'list'
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// If this command is meant to be a parent (requiring subcommands like 'eos delphi list agents'),
		// then its RunE should indicate missing subcommand and display its own help.
		otelzap.Ctx(rc.Ctx).Info("Command called without subcommand",
			zap.String("command", "eos delphi list"),
		)

		fmt.Println(" Missing subcommand for 'eos delphi list'.")
		fmt.Println("  Run `eos delphi list --help` to see available options for listing resources.")
		_ = cmd.Help() // Print built-in help for 'list' command
		return nil
	}),
}

func init() {
	// You would typically add subcommands specific to 'list' here.
	// For example, if you want 'eos delphi list agents' or 'eos delphi list rules':
	// ListCmd.AddCommand(NewListAgentsCmd()) // Assuming you have an agents subcommand
	// ListCmd.AddCommand(NewListRulesCmd())   // Assuming you have a rules subcommand

	// Flags for listing commands might include:
	// ListCmd.PersistentFlags().StringVarP(&filter, "filter", "f", "", "Filter results by a specific criteria")
	// ListCmd.PersistentFlags().IntVarP(&limit, "limit", "l", 100, "Maximum number of items to return")
	// ListCmd.PersistentFlags().IntVarP(&offset, "offset", "o", 0, "Starting offset for pagination")
}
