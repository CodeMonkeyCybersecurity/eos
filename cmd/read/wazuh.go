/* cmd/read/wazuh.go - Refactored to use flags for variants */

package read

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// Package-level variable used by multiple wazuh subcommands
var showSecrets bool

var readWazuhCmd = &cobra.Command{
	Use:   "wazuh",
	Short: "Read Wazuh data",
	Long: `Read Wazuh data and status information.

Available flags (variants):
  --ccs        Read Wazuh MSSP platform status and information
  --version    Show Wazuh version information

Available subcommands:
  agents       Watch agents table for real-time changes
  api          Interact with Wazuh API
  config       Read Wazuh configuration
  credentials  View Wazuh credentials
  users        View Wazuh users
  keepalive    Check Wazuh keepalive status
  inspect      Inspect Wazuh components and pipeline

Examples:
  # Show main Wazuh data (default)
  eos read wazuh

  # Show MSSP platform status
  eos read wazuh --ccs

  # Show version information
  eos read wazuh --version

  # Watch agents (subcommand)
  eos read wazuh agents --limit 25

  # Show help for subcommand
  eos read wazuh agents --help`,
	Aliases: []string{"inspect", "get"},
	RunE:    eos.Wrap(runReadWazuh),
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
	// Add flags for command variants (formerly separate top-level commands)
	readWazuhCmd.Flags().Bool("ccs", false, "Read Wazuh MSSP platform status")
	readWazuhCmd.Flags().Bool("version", false, "Show Wazuh version information")

	// Add subcommands (these remain as subcommands - good UX)
	readWazuhCmd.AddCommand(wazuhAgentsCmd)
	readWazuhCmd.AddCommand(ReadKeepAliveCmd)
	readWazuhCmd.AddCommand(ReadAPICmd)
	readWazuhCmd.AddCommand(ReadConfigCmd)
	readWazuhCmd.AddCommand(ReadCredentialsCmd)
	readWazuhCmd.AddCommand(ReadUsersCmd)
	readWazuhCmd.AddCommand(inspectCmd)
}

// runReadWazuh routes to the appropriate handler based on flags
func runReadWazuh(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get flags
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
		return fmt.Errorf("only one flag can be specified at a time (--ccs or --version)")
	}

	// Route to appropriate handler based on flag
	if ccs {
		logger.Debug("Routing to Wazuh CCS handler")
		return runReadWazuhCCS(rc, cmd, args)
	}

	if version {
		logger.Debug("Routing to Wazuh version handler")
		return runReadWazuhVersion(rc, cmd, args)
	}

	// No flags and no subcommands = show help
	// Note: Cobra handles subcommands automatically before we reach here
	logger.Info("terminal prompt: No flags or subcommands provided")
	logger.Info("terminal prompt: Run 'eos read wazuh --help' to see available options")
	return cmd.Help()
}
