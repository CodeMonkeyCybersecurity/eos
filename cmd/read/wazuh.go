/* cmd/wazuh/inspect/inspect.go */

package read

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	showSecrets bool
)

var readWazuhCmd = &cobra.Command{
	Use:   "wazuh",
	Short: "Read Wazuh (Wazuh) data",
	Long: `The 'read' command provides diagnostic and introspection tools for your Wazuh (Wazuh) instance.

Use this command to view configuration details, authentication info, 
user permissions, versioning data, keepalive status, and other useful insights.

Subcommands are required to specify which type of information to read.`,
	Aliases: []string{"inspect", "get"}, // Keep aliases 'inspect' and 'get' if desired
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// If this command is meant to be a parent (requiring subcommands like 'eos wazuh inspect alerts'),
		// then its RunE should indicate missing subcommand and display its own help.
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("'eos wazuh read' was called without a subcommand")

		logger.Info("terminal prompt: Missing subcommand for 'eos wazuh read'.")                               // More specific message
		logger.Info("terminal prompt: Run `eos wazuh read --help` to see available options for reading data.") // More specific advice
		_ = cmd.Help()                                                                                         // Print built-in help for 'read' command
		return nil
	}),
}

// inspectCmd provides inspection tools for Wazuh components
var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect Wazuh components and pipeline functionality",
	Long: `Interactive inspection tools for Wazuh monitoring system.
		
Available commands:
  pipeline-functionality - Interactive dashboard for pipeline monitoring
  verify-pipeline-schema  - Verify database schema matches schema.sql`,
	Aliases: []string{"get", "read"},
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

func init() {
	// Add subcommands to the wazuh read command
	readWazuhCmd.AddCommand(wazuhAgentsCmd)
	readWazuhCmd.AddCommand(ReadKeepAliveCmd)

	// Add the inspect command with its subcommands

	readWazuhCmd.AddCommand(inspectCmd)

	// Add any flags specific to 'read' itself, if it were a terminal command or had persistent flags.
	// ReadCmd.Flags().BoolVarP(&showSecrets, "show-secrets", "s", false, "Show sensitive secret values (use with caution)")
}
