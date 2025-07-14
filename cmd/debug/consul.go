package debug

import (
	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/debug"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

var consulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Debug Consul service installation and configuration",
	Long: `Debug Consul provides comprehensive troubleshooting for Consul service issues.

This command will:
- Check for port conflicts on Consul ports (HTTP and DNS)
- Identify and optionally clean up lingering processes
- Analyze Consul configuration for common issues
- Test manual startup with detailed error reporting
- Review systemd service configuration
- Analyze extended logs from journalctl
- Provide recommended fixes based on findings`,
	RunE: eos_cli.Wrap(runDebugConsul),
}

func init() {
	debugCmd.AddCommand(consulCmd)
	
	// Add flags
	consulCmd.Flags().Bool("fix", false, "Attempt to automatically fix common issues")
	consulCmd.Flags().Bool("kill-processes", false, "Kill lingering Consul processes")
	consulCmd.Flags().Bool("test-start", false, "Test manual Consul startup")
	consulCmd.Flags().Bool("minimal-config", false, "Test with minimal configuration")
	consulCmd.Flags().Int("log-lines", 100, "Number of log lines to display")
}

func runDebugConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// Parse flags
	config := &debug.Config{
		AutoFix:        cmd.Flag("fix").Value.String() == "true",
		KillProcesses:  cmd.Flag("kill-processes").Value.String() == "true",
		TestStart:      cmd.Flag("test-start").Value.String() == "true",
		MinimalConfig:  cmd.Flag("minimal-config").Value.String() == "true",
		LogLines:       100, // Default, will parse from flag
	}
	
	// Parse log lines
	if logLines, err := cmd.Flags().GetInt("log-lines"); err == nil {
		config.LogLines = logLines
	}
	
	// Run debug diagnostics
	return debug.RunDiagnostics(rc, config)
}