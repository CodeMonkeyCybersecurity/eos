// cmd/debug/bionicgpt.go
// BionicGPT installation and runtime diagnostic command using debug framework

package debug

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
	debugbionicgpt "github.com/CodeMonkeyCybersecurity/eos/pkg/debug/bionicgpt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	bionicgptDebugFormat   string
	bionicgptDebugOutput   string
	bionicgptDebugSanitize bool
	bionicgptDebugShowAll  bool
)

var bionicgptDebugCmd = &cobra.Command{
	Use:   "bionicgpt",
	Short: "Comprehensive BionicGPT diagnostics and troubleshooting",
	Long: `Collect and analyze comprehensive BionicGPT diagnostic information.

This command performs extensive checks on:
- Installation status and directory structure
- Docker daemon and container status
- All service containers (app, postgres, embeddings, RAG, chunking, LiteLLM)
- PostgreSQL database health and connectivity
- Docker volumes and data persistence
- Port bindings and network accessibility
- Container logs for errors
- Resource usage (CPU, memory)
- Ollama integration (for local embeddings)

EXAMPLES:
  # Run diagnostics with text output
  sudo eos debug bionicgpt

  # Save to file
  sudo eos debug bionicgpt --output=/tmp/bionicgpt-debug.txt

  # JSON format for automation
  sudo eos debug bionicgpt --format=json

  # Markdown format for GitHub issues
  sudo eos debug bionicgpt --format=markdown > issue.md

  # Sanitize sensitive data before sharing
  sudo eos debug bionicgpt --sanitize --output=bionicgpt-debug-safe.txt

  # Show all results including skipped checks
  sudo eos debug bionicgpt --show-all`,

	RunE: eos_cli.WrapDebug("bionicgpt", runBionicGPTDebug),
}

func init() {
	bionicgptDebugCmd.Flags().StringVar(&bionicgptDebugFormat, "format", "text", "Output format: text, json, markdown")
	bionicgptDebugCmd.Flags().StringVar(&bionicgptDebugOutput, "output", "", "Save output to file instead of stdout")
	bionicgptDebugCmd.Flags().BoolVar(&bionicgptDebugSanitize, "sanitize", false, "Redact sensitive information (passwords, keys)")
	bionicgptDebugCmd.Flags().BoolVar(&bionicgptDebugShowAll, "show-all", false, "Show all checks including skipped ones")

	debugCmd.AddCommand(bionicgptDebugCmd)
}

func runBionicGPTDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting BionicGPT diagnostics",
		zap.String("format", bionicgptDebugFormat),
		zap.Bool("sanitize", bionicgptDebugSanitize),
		zap.Bool("show_all", bionicgptDebugShowAll),
		zap.String("output_file", bionicgptDebugOutput))

	// Create collector with appropriate formatter
	var formatter debug.Formatter
	logger.Debug("Initializing diagnostic formatter", zap.String("format", bionicgptDebugFormat))

	switch bionicgptDebugFormat {
	case "json":
		formatter = debug.NewJSONFormatter(true) // Pretty JSON
		logger.Debug("Using JSON formatter with pretty printing enabled")
	case "markdown":
		formatter = debug.NewMarkdownFormatter()
		logger.Debug("Using Markdown formatter")
	default:
		textFormatter := debug.NewTextFormatter()
		textFormatter.ShowSkipped = bionicgptDebugShowAll
		formatter = textFormatter
		logger.Debug("Using text formatter", zap.Bool("show_skipped", bionicgptDebugShowAll))
	}

	collector := debug.NewCollector("BionicGPT", formatter)
	logger.Debug("Created diagnostic collector", zap.String("component", "BionicGPT"))

	// Add all BionicGPT diagnostics
	allDiagnostics := debugbionicgpt.AllDiagnostics()

	logger.Debug("Registering diagnostics",
		zap.Int("diagnostics_count", len(allDiagnostics)))

	collector.Add(allDiagnostics...)

	logger.Info("Registered diagnostics", zap.Int("total", len(allDiagnostics)))

	// Run diagnostics
	logger.Info("Running diagnostics collection", zap.Int("checks_to_run", len(allDiagnostics)))
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

	// Create analyzer with BionicGPT-specific rules
	logger.Debug("Initializing diagnostic analyzer")
	analyzer := debug.NewAnalyzer("bionicgpt")

	rules := debugbionicgpt.BionicGPTAnalysisRules()
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
	logger.Debug("Generating formatted output", zap.String("format", bionicgptDebugFormat))
	var output string

	if bionicgptDebugFormat == "text" || bionicgptDebugFormat == "" {
		logger.Debug("Generating text format with executive summary and detailed diagnostics")

		// Add executive summary at top (shows root cause immediately)
		logger.Debug("Generating executive summary")
		execSummary := debugbionicgpt.GenerateExecutiveSummary(report, analysis)
		output = execSummary

		logger.Debug("Formatting diagnostic report")
		output += formatter.Format(report)
		output += "\n\n"

		logger.Debug("Formatting analysis results")
		output += debug.FormatAnalysis(analysis)
		output += "\n\n"

		// Add next steps
		logger.Debug("Generating next steps recommendations")
		nextSteps := debugbionicgpt.GenerateNextSteps(report, analysis)
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
	if bionicgptDebugSanitize {
		logger.Info("Sanitizing sensitive information from output")
		originalSize := len(output)
		output = sanitizeBionicGPTOutput(output)
		logger.Debug("Sanitization complete",
			zap.Int("original_size", originalSize),
			zap.Int("sanitized_size", len(output)))
	}

	// Output to file or stdout
	if bionicgptDebugOutput != "" {
		logger.Info("Writing diagnostic report to file",
			zap.String("file", bionicgptDebugOutput),
			zap.Int("size_bytes", len(output)))

		if err := os.WriteFile(bionicgptDebugOutput, []byte(output), shared.ConfigFilePerm); err != nil {
			logger.Error("Failed to write output file",
				zap.String("file", bionicgptDebugOutput),
				zap.Error(err))
			return fmt.Errorf("failed to write output file: %w", err)
		}

		logger.Info("Diagnostic report saved successfully",
			zap.String("file", bionicgptDebugOutput),
			zap.Int("size_bytes", len(output)))
		fmt.Printf("Diagnostic report saved to: %s\n", bionicgptDebugOutput)
	} else {
		logger.Debug("Writing diagnostic report to stdout")
		fmt.Print(output)
	}

	logger.Info("BionicGPT diagnostics completed successfully")

	return nil
}

// sanitizeBionicGPTOutput redacts sensitive information
func sanitizeBionicGPTOutput(output string) string {
	sanitized := output

	// Redact PostgreSQL passwords
	sanitized = strings.ReplaceAll(sanitized, "POSTGRES_PASSWORD=", "POSTGRES_PASSWORD=[REDACTED]")

	// Redact Azure OpenAI keys
	sanitized = strings.ReplaceAll(sanitized, "AZURE_API_KEY=", "AZURE_API_KEY=[REDACTED]")
	sanitized = strings.ReplaceAll(sanitized, "AZURE_OPENAI_API_KEY=", "AZURE_OPENAI_API_KEY=[REDACTED]")

	// Redact JWT secrets
	sanitized = strings.ReplaceAll(sanitized, "JWT_SECRET=", "JWT_SECRET=[REDACTED]")

	// Redact LiteLLM master key
	sanitized = strings.ReplaceAll(sanitized, "LITELLM_MASTER_KEY=", "LITELLM_MASTER_KEY=[REDACTED]")

	// Redact connection strings with passwords
	lines := strings.Split(sanitized, "\n")
	for i, line := range lines {
		if strings.Contains(line, "postgresql://") && strings.Contains(line, "@") {
			// Redact password in connection string
			lines[i] = "DATABASE_URL=postgresql://[REDACTED]@[REDACTED]"
		}
		if strings.Contains(line, "password=") {
			lines[i] = strings.Split(line, "password=")[0] + "password=[REDACTED]"
		}
	}
	sanitized = strings.Join(lines, "\n")

	return sanitized
}
