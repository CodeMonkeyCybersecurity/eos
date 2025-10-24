package debug

import (
	"bytes"
	"io"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/debug"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

var consulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Debug Consul service installation and configuration",
	Long: `Debug Consul provides comprehensive troubleshooting for Consul service issues.

Diagnostic checks performed:
1. Consul binary verification (existence, permissions, version)
2. File permissions (config, data, and log directories)
3. Configuration analysis (bind_addr, advertise_addr, client_addr, retry_join)
4. Systemd service configuration
5. Lingering processes detection
6. Network configuration (interfaces, IP addresses)
7. Port connectivity (HTTP API, gRPC, DNS, Serf, RPC)
8. Port conflict detection
9. Log analysis (errors, warnings, startup issues)
10. Detailed port binding analysis (which addresses ports are bound to)
11. Cluster state (members, leader, raft peers)
12. Retry join target connectivity (reachability of join targets)
13. Vault-Consul connectivity (critical for Vault storage backend)

Flags:
  --fix              Automatically fix common issues
  --kill-processes   Kill lingering Consul processes
  --test-start       Test manual Consul startup
  --minimal-config   Test with minimal configuration
  --log-lines N      Number of log lines to analyze (default: 100)

Example:
  eos debug consul
  eos debug consul --fix
  eos debug consul --kill-processes --test-start

Output is automatically saved to ~/.eos/debug/eos-debug-consul-{timestamp}.txt`,
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
	// Capture stdout to save diagnostic output to file
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Buffer to capture output
	outputChan := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outputChan <- buf.String()
	}()

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
	err := debug.RunDiagnostics(rc, config)

	// Restore stdout and get captured output
	w.Close()
	os.Stdout = oldStdout
	capturedOutput := <-outputChan

	// Save captured output to file
	saveDebugOutput(rc, "consul", capturedOutput)

	return err
}