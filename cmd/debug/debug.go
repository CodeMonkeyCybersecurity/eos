// Package debug provides debugging commands for troubleshooting Eos services
package debug

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// debugCmd represents the debug command
var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debug and troubleshoot Eos services",
	Long: `Debug provides comprehensive troubleshooting tools for various Eos services.

Available subcommands:
  bootstrap       - Debug bootstrap process and infrastructure setup
  consul          - Debug Consul service installation and configuration issues
  ssh             - Debug SSH connectivity and key authentication issues
  wazuh          - Debug Wazuh (Iris/Temporal) webhook integration
  mattermost      - Debug Mattermost deployment and troubleshoot issues
  iris           - Debug Iris security alert processing system
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

// saveDebugOutput is a universal helper for saving debug command output to ~/.eos/debug/
// This replaces the now-deprecated WrapDebug functionality with a simpler approach.
//
// Usage in debug commands:
//
//	func runDebugConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
//	    // Capture output using bytes.Buffer or strings.Builder
//	    var output strings.Builder
//	    fmt.Fprintf(&output, "Diagnostic output here...\n")
//
//	    // Run diagnostics...
//	    err := debug.RunDiagnostics(rc, config)
//
//	    // Save output to file (non-fatal if fails)
//	    saveDebugOutput(rc, "consul", output.String())
//
//	    return err
//	}
//
// File saved to: ~/.eos/debug/eos-debug-{serviceName}-{timestamp}.txt
func saveDebugOutput(rc *eos_io.RuntimeContext, serviceName string, output string) {
	logger := otelzap.Ctx(rc.Ctx)

	// Skip if no output
	if output == "" {
		logger.Debug("No output to save")
		return
	}

	// Determine save directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		logger.Warn("Could not determine home directory, using /tmp",
			zap.Error(err))
		homeDir = "/tmp"
	}

	debugDir := filepath.Join(homeDir, ".eos", "debug")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(debugDir, 0755); err != nil {
		logger.Warn("Failed to create debug directory, output not saved",
			zap.String("dir", debugDir),
			zap.Error(err))
		return
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("eos-debug-%s-%s.txt", serviceName, timestamp)
	filePath := filepath.Join(debugDir, filename)

	// Write output to file
	if err := os.WriteFile(filePath, []byte(output), 0644); err != nil {
		logger.Warn("Failed to save debug output to file",
			zap.String("file", filePath),
			zap.Error(err))
		return
	}

	logger.Info("Debug output saved to file",
		zap.String("file", filePath),
		zap.Int("size_bytes", len(output)))

	// Print to user
	fmt.Printf("\nDiagnostic output saved to: %s\n", filePath)
}
