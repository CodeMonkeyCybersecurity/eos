// Package debug provides debugging commands for troubleshooting Eos services
package debug

import (
	"github.com/spf13/cobra"
)

// debugCmd represents the debug command
var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debug and troubleshoot Eos services",
	Long: `Debug provides comprehensive troubleshooting tools for various Eos services.

Available subcommands:
  bootstrap       - Debug bootstrap process and infrastructure setup
  consul          - Debug Consul service installation and configuration issues
  delphi          - Debug Delphi (Metis/Temporal) webhook integration
  metis           - Debug Metis security alert processing system
  openwebui       - Debug OpenWebUI backup and update issues
  watchdog-traces - Analyze resource watchdog traces from previous runs

Each subcommand performs deep diagnostics specific to that component,
identifies issues, and provides actionable recommendations for fixes.`,
}

func init() {
	// Register subcommands here
	debugCmd.AddCommand(consulCmd)
	debugCmd.AddCommand(openwebuiDebugCmd)
	debugCmd.AddCommand(watchdogTracesCmd)
}

// GetDebugCmd returns the debug command for registration with root
func GetDebugCmd() *cobra.Command {
	return debugCmd
}