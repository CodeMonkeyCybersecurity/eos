package read

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var (
	showSecrets bool
)

var ReadCmd = &cobra.Command{
	Use:   "read",
	Short: "Read Delphi (Wazuh) data",
	Long: `The 'read' command provides diagnostic and introspection tools for your Delphi (Wazuh) instance.

Use this command to view configuration details, authentication info, 
user permissions, versioning data, keepalive status, and other useful insights.

Subcommands are required to specify which type of information to read.`,
	Aliases: []string{"inspect", "get"}, // Keep aliases 'inspect' and 'get' if desired
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// If this command is meant to be a parent (requiring subcommands like 'eos delphi inspect alerts'),
		// then its RunE should indicate missing subcommand and display its own help.
		otelzap.Ctx(rc.Ctx).Info("'eos delphi read' was called without a subcommand")

		fmt.Println("❌ Missing subcommand for 'eos delphi read'.")                               // More specific message
		fmt.Println("ℹ️  Run `eos delphi read --help` to see available options for reading data.") // More specific advice
		_ = cmd.Help()                                                                              // Print built-in help for 'read' command
		return nil
	}),
}

func init() {
	// You would typically add subcommands specific to 'read' here.
	// For example, if you want 'eos delphi read alerts' or 'eos delphi read config':
	// ReadCmd.AddCommand(NewReadAlertsCmd()) // Assuming you have an alerts subcommand
	// ReadCmd.AddCommand(NewReadConfigCmd()) // Assuming you have a config subcommand

	// Add any flags specific to 'read' itself, if it were a terminal command or had persistent flags.
	// ReadCmd.Flags().BoolVarP(&showSecrets, "show-secrets", "s", false, "Show sensitive secret values (use with caution)")
}
