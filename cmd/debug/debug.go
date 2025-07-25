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
  consul - Debug Consul service installation and configuration issues
  watchdog-traces - Analyze resource watchdog traces from previous runs`,
}

func init() {
	// Register subcommands here
	debugCmd.AddCommand(consulCmd)
	debugCmd.AddCommand(watchdogTracesCmd)
}

// GetDebugCmd returns the debug command for registration with root
func GetDebugCmd() *cobra.Command {
	return debugCmd
}