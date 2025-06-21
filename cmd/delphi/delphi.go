// cmd/delphi/delphi.go
package delphi

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/create"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/delete"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/read" // This is delphi's 'read' subcommand
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/sync"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delphi/update"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared" // Assuming shared.SafeHelp is here
	"github.com/spf13/cobra"
)

// DelphiCmd groups commands related to managing Delphi (Wazuh) components.
var DelphiCmd = &cobra.Command{
	Use:   "delphi",
	Short: "Manage Delphi (Wazuh) components",
	Long:  "Commands related to Wazuh and Delphi integrations such as install, remove, and inspect.",
	// RunE here is good. If 'eos delphi' is called without subcommands,
	// it will print the specific help for 'delphi' thanks to shared.SafeHelp(cmd).
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		fmt.Println("❌ Missing subcommand for 'eos delphi'.") // More specific message
		shared.SafeHelp(cmd)                                  // This should now correctly print help for DelphiCmd
		return nil                                            // Return nil so Cobra doesn't print its own generic error/usage
	}),
}

func init() {
	// Register subcommands to DelphiCmd
	DelphiCmd.AddCommand(create.CreateCmd)
	DelphiCmd.AddCommand(read.ReadCmd) // This 'read' is specific to 'delphi'
	DelphiCmd.AddCommand(delete.DeleteCmd)
	DelphiCmd.AddCommand(update.UpdateCmd)
	DelphiCmd.AddCommand(sync.SyncCmd)

	// TODO: Example persistent flags: DelphiCmd.PersistentFlags().String("config", "", "Path to the Delphi configuration file")
}

// log is a package-level variable for the Zap logger.
// This init() block seems empty or related to a different concern, keeping it as is.
func init() {
	// Initialize the shared logger for the entire deploy package
}
