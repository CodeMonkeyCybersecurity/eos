// cmd/read/wazuh_refactored.go
// REFACTORED: Consolidated wazuh commands with flag-based variants

package read

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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

func runReadWazuh(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check which flag was provided
	ccs, _ := cmd.Flags().GetBool("ccs")
	version, _ := cmd.Flags().GetBool("version")

	// Validate: only one flag at a time
	flagCount := 0
	if ccs {
		flagCount++
	}
	if version {
		flagCount++
	}

	if flagCount > 1 {
		return fmt.Errorf("only one flag can be specified at a time")
	}

	// Route to appropriate handler based on flag
	if ccs {
		logger.Info("Routing to Wazuh CCS handler")
		return runReadWazuhCCS(rc, cmd, args)
	}

	if version {
		logger.Info("Routing to Wazuh version handler")
		return runReadWazuhVersion(rc, cmd, args)
	}

	// Default behavior: show main Wazuh data
	// Check if a subcommand was called (Cobra will handle that automatically)
	// If we reach here, no flags and no subcommands, show help
	if len(args) == 0 {
		logger.Info("No flags or subcommands provided for 'eos read wazuh'")
		logger.Info("terminal prompt: Run 'eos read wazuh --help' to see available options")
		return cmd.Help()
	}

	// If args provided but no matching subcommand, show error
	return fmt.Errorf("unknown argument: %s", args[0])
}

// runReadWazuhVersion shows Wazuh version information
// This function should be extracted from wazuh_version.go
func runReadWazuhVersion(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Showing Wazuh version information")

	// TODO: Implement or call existing implementation from wazuh_version.go
	// For now, placeholder:
	logger.Info("terminal prompt: Wazuh Version: 4.x (implementation pending)")

	return nil
}

// Note: runReadWazuhCCS is already defined in wazuh_ccs.go
// We'll need to make it callable from here
