// cmd/debug/vault_refactored.go
// Refactored vault debug command using pkg/debug framework

package debug

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
	debugvault "github.com/CodeMonkeyCybersecurity/eos/pkg/debug/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	vaultDebugFormat   string
	vaultDebugOutput   string
	vaultDebugSanitize bool
	vaultDebugShowAll  bool
)

var vaultDebugCmd = &cobra.Command{
	Use:   "vault",
	Short: "Comprehensive Vault diagnostics and troubleshooting",
	Long: `Collect and analyze comprehensive Vault diagnostic information.

This command performs extensive checks on:
- Binary installation and version
- Configuration files and validation
- Directory permissions and ownership
- Systemd service status and logs
- Network connectivity and ports
- TLS configuration
- User/group configuration
- Environment variables
- Resource usage

EXAMPLES:
  # Run diagnostics with text output
  sudo eos debug vault

  # Save to file
  sudo eos debug vault --output=/tmp/vault-debug.txt

  # JSON format for automation
  sudo eos debug vault --format=json

  # Markdown format for GitHub issues
  sudo eos debug vault --format=markdown > issue.md

  # Sanitize sensitive data before sharing
  sudo eos debug vault --sanitize --output=vault-debug-safe.txt

  # Show all results including skipped checks
  sudo eos debug vault --show-all`,

	RunE: eos_cli.Wrap(runVaultDebug),
}

func init() {
	vaultDebugCmd.Flags().StringVar(&vaultDebugFormat, "format", "text", "Output format: text, json, markdown")
	vaultDebugCmd.Flags().StringVar(&vaultDebugOutput, "output", "", "Save output to file instead of stdout")
	vaultDebugCmd.Flags().BoolVar(&vaultDebugSanitize, "sanitize", false, "Redact sensitive information (tokens, paths)")
	vaultDebugCmd.Flags().BoolVar(&vaultDebugShowAll, "show-all", false, "Show all checks including skipped ones")

	debugCmd.AddCommand(vaultDebugCmd)
}

func runVaultDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault diagnostics using framework")

	// Create collector with appropriate formatter
	var formatter debug.Formatter
	switch vaultDebugFormat {
	case "json":
		formatter = debug.NewJSONFormatter(true) // Pretty JSON
	case "markdown":
		formatter = debug.NewMarkdownFormatter()
	default:
		textFormatter := debug.NewTextFormatter()
		textFormatter.ShowSkipped = vaultDebugShowAll
		formatter = textFormatter
	}

	collector := debug.NewCollector("Vault", formatter)

	// Add all vault diagnostics
	collector.Add(debugvault.AllDiagnostics()...)

	// Run diagnostics
	output, err := collector.RunAndFormat(rc.Ctx)
	if err != nil {
		return fmt.Errorf("diagnostics failed: %w", err)
	}

	// Sanitize if requested
	if vaultDebugSanitize {
		output = sanitizeOutput(output)
	}

	// Output to file or stdout
	if vaultDebugOutput != "" {
		if err := os.WriteFile(vaultDebugOutput, []byte(output), 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		logger.Info("Diagnostic report saved",
			zap.String("file", vaultDebugOutput),
			zap.Int("size", len(output)))
		fmt.Printf("Diagnostic report saved to: %s\n", vaultDebugOutput)
	} else {
		fmt.Print(output)
	}

	return nil
}

// sanitizeOutput redacts sensitive information
func sanitizeOutput(output string) string {
	// TODO: Implement proper sanitization
	// - Redact tokens (s.hvs.... )
	// - Redact IP addresses (optionally)
	// - Redact file paths (optionally)
	// - Redact usernames/passwords in logs
	return output
}
