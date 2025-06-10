package inspect

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

// ⚠️ IMPORTANT CHANGE: Rename this command to avoid confusion with top-level 'read'.
// Let's call it InspectCmd as your output suggested "eos delphi inspect".
// If 'read' is truly the name, then stick with 'ReadCmd' but clarify its usage.
// Given your prompt output, it appears 'inspect' is the intended name here.
// Let's assume you want 'eos delphi inspect' with the 'read' alias.

var InspectCmd = &cobra.Command{ // Renamed from ReadCmd to InspectCmd for clarity
    Use:   "inspect", // Changed Use to "inspect"
    Short: "Inspect Delphi (Wazuh) data",
    Long: `The 'inspect' command provides diagnostic and introspection tools for your Delphi (Wazuh) instance.

Use this command to view configuration details, authentication info, 
user permissions, versioning data, keepalive status, and other useful insights.

Subcommands are required to specify which type of information to inspect.`,
    Aliases: []string{"read", "get"}, // Keep aliases 'read' and 'get' if desired
    RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
        // If this command is meant to be a parent (requiring subcommands like 'eos delphi inspect alerts'),
        // then its RunE should indicate missing subcommand and display its own help.
        otelzap.Ctx(rc.Ctx).Info("'eos delphi inspect' was called without a subcommand")

        fmt.Println("❌ Missing subcommand for 'eos delphi inspect'.") // More specific message
        fmt.Println("ℹ️  Run `eos delphi inspect --help` to see available options for inspection.") // More specific advice
        _ = cmd.Help() // Print built-in help for 'inspect' command
        return nil
    }),
}

func init() {
    // You would typically add subcommands specific to 'inspect' here.
    // For example, if you want 'eos delphi inspect alerts' or 'eos delphi inspect config':
    // InspectCmd.AddCommand(NewInspectAlertsCmd()) // Assuming you have an alerts subcommand
    // InspectCmd.AddCommand(NewInspectConfigCmd()) // Assuming you have a config subcommand

    // Add any flags specific to 'inspect' itself, if it were a terminal command or had persistent flags.
    // InspectCmd.Flags().BoolVarP(&showSecrets, "show-secrets", "s", false, "Show sensitive secret values (use with caution)")
}