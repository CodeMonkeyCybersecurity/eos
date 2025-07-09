// cmd/delphi/services/analyze-ab-results.go
package read

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/cmd_helpers"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	analyzeABResultsHours      int
	analyzeABResultsExport     string
	analyzeABResultsOutputFile string
	analyzeABResultsCompare    []string
	analyzeABResultsQuiet      bool
)

// analyzeABResultsCmd analyzes A/B testing results for prompt optimization
var analyzeABResultsCmd = &cobra.Command{
	Use:   "analyze-ab-results",
	Short: "Analyze A/B testing results for prompt optimization",
	Long: `Analyze A/B testing results from the prompt-ab-tester service to evaluate prompt effectiveness.

This command runs the ab-test-analyzer.py script to provide:
- Performance comparison across prompt variants
- Statistical significance testing  
- Cost analysis and ROI calculations
- Optimization recommendations
- Export capabilities for reporting

The analysis includes metrics such as:
- Success rates and error rates
- Response times and token usage
- Cost per request and efficiency ratios
- User satisfaction and business impact

Examples:
  eos read analyze-ab-results
  eos read analyze-ab-results --hours 168 --export csv
  eos read analyze-ab-results --compare cybersobar delphi_notify_long
  eos read analyze-ab-results --export json --output /tmp/ab-results.json`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Starting A/B testing results analysis",
			zap.Int("hours_back", analyzeABResultsHours),
			zap.String("export_format", analyzeABResultsExport),
			zap.Bool("quiet", analyzeABResultsQuiet))

		// Create file service container
		fileContainer, err := cmd_helpers.NewFileServiceContainer(rc)
		if err != nil {
			return fmt.Errorf("failed to initialize file operations: %w", err)
		}

		// Verify analyzer script exists
		analyzerScript := "/usr/local/bin/ab-test-analyzer.py"
		if !fileContainer.FileExists(analyzerScript) {
			return fmt.Errorf("A/B testing analyzer not found: %s (deploy with: eos delphi services update prompt-ab-tester)", analyzerScript)
		}

		// Build command arguments
		cmdArgs := []string{
			analyzerScript,
			"--hours", strconv.Itoa(analyzeABResultsHours),
		}

		if analyzeABResultsExport != "" {
			cmdArgs = append(cmdArgs, "--export", analyzeABResultsExport)
		}

		if analyzeABResultsOutputFile != "" {
			cmdArgs = append(cmdArgs, "--output", analyzeABResultsOutputFile)
		}

		if len(analyzeABResultsCompare) == 2 {
			cmdArgs = append(cmdArgs, "--compare", analyzeABResultsCompare[0], analyzeABResultsCompare[1])
		} else if len(analyzeABResultsCompare) > 0 {
			return fmt.Errorf("compare requires exactly 2 variant names")
		}

		if analyzeABResultsQuiet {
			cmdArgs = append(cmdArgs, "--quiet")
		}

		logger.Info(" Running A/B testing analysis",
			zap.String("analyzer", analyzerScript),
			zap.Strings("arguments", cmdArgs[1:]))

		// Execute analyzer
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "python3",
			Args:    cmdArgs,
		})

		if err != nil {
			logger.Error(" Analysis failed",
				zap.Error(err),
				zap.String("output", output))
			return fmt.Errorf("A/B testing analysis failed: %w", err)
		}

		if !analyzeABResultsQuiet {
			// Display output
			if output != "" {
				lines := strings.Split(output, "\n")
				for _, line := range lines {
					if strings.TrimSpace(line) != "" {
						logger.Info(line)
					}
				}
			}
		}

		logger.Info(" A/B testing analysis completed")

		// Show next steps if export was used
		if analyzeABResultsExport != "" && analyzeABResultsOutputFile != "" {
			logger.Info(" Results exported",
				zap.String("file", analyzeABResultsOutputFile),
				zap.String("format", analyzeABResultsExport))
			logger.Info(" Next steps:")
			logger.Info("   - Review exported results for insights")
			logger.Info("   - Consider adjusting prompt weights in /opt/delphi/ab-test-config.json")
			logger.Info("   - Monitor ongoing experiments with: eos delphi services logs prompt-ab-tester")
		}

		return nil
	}),
}

func init() {
	analyzeABResultsCmd.Flags().IntVar(&analyzeABResultsHours, "hours", 24, "Hours of data to analyze (default: 24)")
	analyzeABResultsCmd.Flags().StringVar(&analyzeABResultsExport, "export", "", "Export format: json, csv, txt")
	analyzeABResultsCmd.Flags().StringVar(&analyzeABResultsOutputFile, "output", "", "Output file path for exported results")
	analyzeABResultsCmd.Flags().StringSliceVar(&analyzeABResultsCompare, "compare", nil, "Compare two specific variants (requires exactly 2 variant names)")
	analyzeABResultsCmd.Flags().BoolVar(&analyzeABResultsQuiet, "quiet", false, "Suppress console output")
}
