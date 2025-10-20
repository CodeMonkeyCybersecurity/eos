// cmd/read/wazuh_refactored.go
// REFACTORED: Consolidated wazuh commands with flag-based variants

package read

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/spf13/cobra"
)

var readWazuhCmdRefactored = &cobra.Command{
	Use:   "wazuh",
	Short: "Read Wazuh data",
	Long: `Read Wazuh data and status information.

Default behavior (no flags):
  Shows main Wazuh data

Available flags:
  --ccs        Read Wazuh MSSP platform status and information
  --version    Show Wazuh version information
  --agents       Watch agents table for real-time changes
  --api          Interact with Wazuh API
  --config       Read Wazuh configuration
  --credentials  View Wazuh credentials
  --users        View Wazuh users
  --keepalive    Check Wazuh keepalive status
  --inspect      Inspect Wazuh components and pipeline

Examples:
  # Show main Wazuh data (default)
  eos read wazuh

  # Show MSSP platform status
  eos read wazuh --ccs

  # Show version information
  eos read wazuh --version

  # Watch agents (subcommand)
  eos read wazuh agents --limit 25

  # Show help for a specific subcommand
  eos read wazuh agents --help`,
	Aliases: []string{"inspect", "get"},
	RunE:    eos.Wrap(runReadWazuh),
}

func init() {
	// Add flags for command variants
	readWazuhCmdRefactored.Flags().Bool("ccs", false, "Read Wazuh MSSP platform status")
	readWazuhCmdRefactored.Flags().Bool("version", false, "Show Wazuh version information")

	// Add subcommands (these remain as subcommands for good UX)
	readWazuhCmdRefactored.AddCommand(wazuhAgentsCmd)
	readWazuhCmdRefactored.AddCommand(ReadKeepAliveCmd)
	readWazuhCmdRefactored.AddCommand(inspectCmd)
	// Add other subcommands as they exist:
	// readWazuhCmdRefactored.AddCommand(wazuhAPICmd)
	// readWazuhCmdRefactored.AddCommand(wazuhConfigCmd)
	// readWazuhCmdRefactored.AddCommand(wazuhCredentialsCmd)
	// readWazuhCmdRefactored.AddCommand(wazuhUsersCmd)
}

// Note: runReadWazuhCCS is already defined in wazuh_ccs.go
// We'll need to make it callable from here
