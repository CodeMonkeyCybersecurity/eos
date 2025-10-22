// cmd/debug/vault_refactored.go
// Refactored vault debug command using pkg/debug framework

package debug

import (
	"fmt"
	"os"
	"strings"

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
	vaultDebugAgent    bool
	vaultDebugAuth     bool
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
- Vault Agent service and authentication
- Authentication and authorization (AppRole, tokens, policies)

DIAGNOSTIC MODES:
  --agent    Vault Agent service diagnostics (service, config, credentials, token, logs)
  --auth     Authentication & authorization deep-dive (policies, permissions, AppRole, token capabilities)

EXAMPLES:
  # Run full diagnostics with text output
  sudo eos debug vault

  # Run Vault Agent-only diagnostics
  sudo eos debug vault --agent

  # Deep-dive authentication troubleshooting (permission denied, policy issues)
  sudo eos debug vault --auth

  # Save to file
  sudo eos debug vault --output=/tmp/vault-debug.txt

  # JSON format for automation
  sudo eos debug vault --format=json

  # Markdown format for GitHub issues
  sudo eos debug vault --format=markdown > issue.md

  # Sanitize sensitive data before sharing
  sudo eos debug vault --sanitize --output=vault-debug-safe.txt

  # Show all results including skipped checks
  sudo eos debug vault --show-all

  # Debug specific authentication flow issues
  sudo eos debug vault --auth --show-all

  # Debug Agent service issues
  sudo eos debug vault --agent --show-all`,

	RunE: eos_cli.WrapDebug("vault", runVaultDebug),
}

func init() {
	vaultDebugCmd.Flags().StringVar(&vaultDebugFormat, "format", "text", "Output format: text, json, markdown")
	vaultDebugCmd.Flags().StringVar(&vaultDebugOutput, "output", "", "Save output to file instead of stdout")
	vaultDebugCmd.Flags().BoolVar(&vaultDebugSanitize, "sanitize", false, "Redact sensitive information (tokens, paths)")
	vaultDebugCmd.Flags().BoolVar(&vaultDebugShowAll, "show-all", false, "Show all checks including skipped ones")
	vaultDebugCmd.Flags().BoolVar(&vaultDebugAgent, "agent", false, "Run Vault Agent diagnostics only (service, config, credentials, token, logs)")
	vaultDebugCmd.Flags().BoolVar(&vaultDebugAuth, "auth", false, "Run authentication & authorization diagnostics (health, AppRole, token, policies, permissions)")

	debugCmd.AddCommand(vaultDebugCmd)
}

func runVaultDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate mutually exclusive flags
	if vaultDebugAgent && vaultDebugAuth {
		return fmt.Errorf("--agent and --auth flags are mutually exclusive; use only one at a time")
	}

	logger.Info("Starting Vault diagnostics",
		zap.String("format", vaultDebugFormat),
		zap.Bool("sanitize", vaultDebugSanitize),
		zap.Bool("show_all", vaultDebugShowAll),
		zap.Bool("agent_mode", vaultDebugAgent),
		zap.Bool("auth_mode", vaultDebugAuth),
		zap.String("output_file", vaultDebugOutput))

	// Create collector with appropriate formatter
	var formatter debug.Formatter
	logger.Debug("Initializing diagnostic formatter", zap.String("format", vaultDebugFormat))

	switch vaultDebugFormat {
	case "json":
		formatter = debug.NewJSONFormatter(true) // Pretty JSON
		logger.Debug("Using JSON formatter with pretty printing enabled")
	case "markdown":
		formatter = debug.NewMarkdownFormatter()
		logger.Debug("Using Markdown formatter")
	default:
		textFormatter := debug.NewTextFormatter()
		textFormatter.ShowSkipped = vaultDebugShowAll
		formatter = textFormatter
		logger.Debug("Using text formatter", zap.Bool("show_skipped", vaultDebugShowAll))
	}

	// Determine component name and diagnostics based on mode
	componentName := "Vault"
	var allDiagnostics []*debug.Diagnostic
	var totalDiagnostics int

	if vaultDebugAgent {
		componentName = "Vault Agent"
		allDiagnostics = debugvault.AgentDiagnostics()
		logger.Debug("Running in Agent-only mode",
			zap.Int("agent_diagnostics", len(allDiagnostics)))
		totalDiagnostics = len(allDiagnostics)
		logger.Info("Registered agent diagnostics", zap.Int("total", totalDiagnostics))
	} else if vaultDebugAuth {
		componentName = "Vault Authentication"
		allDiagnostics = debugvault.AuthDiagnostics()
		logger.Debug("Running in Auth-only mode",
			zap.Int("auth_diagnostics", len(allDiagnostics)))
		totalDiagnostics = len(allDiagnostics)
		logger.Info("Registered auth diagnostics", zap.Int("total", totalDiagnostics))
	} else {
		// Full mode: all diagnostics including TLS
		allDiagnostics = debugvault.AllDiagnostics()
		tlsDiagnostic := debugvault.TLSDiagnostic()
		logger.Debug("Running in full mode",
			zap.Int("standard_diagnostics", len(allDiagnostics)),
			zap.Bool("tls_diagnostic", true))
		allDiagnostics = append(allDiagnostics, tlsDiagnostic)
		totalDiagnostics = len(allDiagnostics)
		logger.Info("Registered diagnostics", zap.Int("total", totalDiagnostics))
	}

	collector := debug.NewCollector(componentName, formatter)
	logger.Debug("Created diagnostic collector", zap.String("component", componentName))
	collector.Add(allDiagnostics...)

	// Run diagnostics
	logger.Info("Running diagnostics collection", zap.Int("checks_to_run", totalDiagnostics))
	report, err := collector.Run(rc.Ctx)
	if err != nil {
		logger.Error("Diagnostics collection failed", zap.Error(err))
		return fmt.Errorf("diagnostics collection failed: %w", err)
	}

	logger.Info("Diagnostics collection completed",
		zap.Int("checks_run", len(report.Results)),
		zap.Int("ok", report.Summary.OK),
		zap.Int("warnings", report.Summary.Warnings),
		zap.Int("errors", report.Summary.Errors),
		zap.Int("skipped", report.Summary.Skipped))

	// Create analyzer with vault-specific rules
	logger.Debug("Initializing diagnostic analyzer")
	analyzer := debug.NewAnalyzer("vault")

	rules := debugvault.VaultAnalysisRules()
	logger.Debug("Loading analysis rules", zap.Int("rule_count", len(rules)))

	for i := range rules {
		analyzer.AddRule(rules[i])
		logger.Debug("Registered analysis rule", zap.Int("rule_number", i+1))
	}

	logger.Info("Analysis rules loaded", zap.Int("total_rules", len(rules)))

	// Perform analysis
	logger.Info("Performing diagnostic analysis")
	analysis := analyzer.Analyze(report)

	logger.Info("Analysis completed",
		zap.Int("critical_issues", len(analysis.CriticalIssues)),
		zap.Int("major_issues", len(analysis.MajorIssues)),
		zap.Int("minor_issues", len(analysis.MinorIssues)),
		zap.Int("warnings", len(analysis.Warnings)),
		zap.String("overall_health", string(analysis.OverallHealth)))

	// Generate output with analysis
	logger.Debug("Generating formatted output", zap.String("format", vaultDebugFormat))
	var output string

	if vaultDebugFormat == "text" || vaultDebugFormat == "" {
		logger.Debug("Generating text format with quick summary and next steps")

		// Add quick health summary at top
		logger.Debug("Generating quick health summary")
		quickSummary := debug.GenerateQuickSummary(report, analysis)
		summaryComponent := "vault"
		if vaultDebugAgent {
			summaryComponent = "vault-agent"
		} else if vaultDebugAuth {
			summaryComponent = "vault-auth"
		}
		output = debug.FormatQuickSummary(quickSummary, summaryComponent)
		output += "\n\n"

		logger.Debug("Formatting diagnostic report")
		output += formatter.Format(report)
		output += "\n\n"

		logger.Debug("Formatting analysis results")
		output += debug.FormatAnalysis(analysis)
		output += "\n\n"

		// Add next steps
		logger.Debug("Generating next steps recommendations")
		nextSteps := debugvault.GenerateNextSteps(report, analysis)
		logger.Debug("Next steps generated", zap.Int("step_count", len(nextSteps)))

		if len(nextSteps) > 0 {
			output += strings.Repeat("=", 80) + "\n"
			output += "RECOMMENDED NEXT STEPS\n"
			output += strings.Repeat("=", 80) + "\n\n"
			for i, step := range nextSteps {
				output += fmt.Sprintf("%d. %s\n", i+1, step)
				logger.Debug("Next step", zap.Int("step", i+1), zap.String("action", step))
			}
			output += "\n"
		}
	} else {
		// JSON/Markdown get full report
		logger.Debug("Using formatter for structured output")
		output = formatter.Format(report)
	}

	logger.Info("Output generated", zap.Int("output_size_bytes", len(output)))

	// Sanitize if requested
	if vaultDebugSanitize {
		logger.Info("Sanitizing sensitive information from output")
		originalSize := len(output)
		output = sanitizeOutput(output)
		logger.Debug("Sanitization complete",
			zap.Int("original_size", originalSize),
			zap.Int("sanitized_size", len(output)))
	}

	// Output to file or stdout
	if vaultDebugOutput != "" {
		logger.Info("Writing diagnostic report to file",
			zap.String("file", vaultDebugOutput),
			zap.Int("size_bytes", len(output)))

		if err := os.WriteFile(vaultDebugOutput, []byte(output), 0644); err != nil {
			logger.Error("Failed to write output file",
				zap.String("file", vaultDebugOutput),
				zap.Error(err))
			return fmt.Errorf("failed to write output file: %w", err)
		}

		logger.Info("Diagnostic report saved successfully",
			zap.String("file", vaultDebugOutput),
			zap.Int("size_bytes", len(output)))
		fmt.Printf("Diagnostic report saved to: %s\n", vaultDebugOutput)
	} else {
		logger.Debug("Writing diagnostic report to stdout")
		fmt.Print(output)
	}

	logger.Info("Vault diagnostics completed successfully")

	return nil
}

// sanitizeOutput redacts sensitive information
func sanitizeOutput(output string) string {
	sanitized := output

	// Redact Vault tokens (s.hvs.*, s.root.*)
	sanitized = strings.ReplaceAll(sanitized, "s.hvs.", "[REDACTED-TOKEN]")
	sanitized = strings.ReplaceAll(sanitized, "s.root.", "[REDACTED-ROOT-TOKEN]")

	// Redact recovery/unseal keys (base64-encoded)
	recoveryKeyPattern := `[A-Za-z0-9+/]{44}==`
	sanitized = strings.ReplaceAll(sanitized, recoveryKeyPattern, "[REDACTED-KEY]")

	// Redact common environment variable values containing secrets
	lines := strings.Split(sanitized, "\n")
	for i, line := range lines {
		if strings.Contains(line, "VAULT_TOKEN=") {
			lines[i] = "VAULT_TOKEN=[REDACTED]"
		}
		if strings.Contains(line, "AWS_SECRET_ACCESS_KEY=") {
			lines[i] = "AWS_SECRET_ACCESS_KEY=[REDACTED]"
		}
	}
	sanitized = strings.Join(lines, "\n")

	return sanitized
}
