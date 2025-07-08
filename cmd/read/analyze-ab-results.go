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

// NewAnalyzeABResultsCmd creates the analyze-ab-results command
func NewAnalyzeABResultsCmd() *cobra.Command {
	var (
		hours      int
		export     string
		outputFile string
		compare    []string
		quiet      bool
	)

	cmd := &cobra.Command{
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
  eos delphi services analyze-ab-results
  eos delphi services analyze-ab-results --hours 168 --export csv
  eos delphi services analyze-ab-results --compare cybersobar delphi_notify_long
  eos delphi services analyze-ab-results --export json --output /tmp/ab-results.json`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info(" Starting A/B testing results analysis",
				zap.Int("hours_back", hours),
				zap.String("export_format", export),
				zap.Bool("quiet", quiet))

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
				"--hours", strconv.Itoa(hours),
			}

			if export != "" {
				cmdArgs = append(cmdArgs, "--export", export)
			}

			if outputFile != "" {
				cmdArgs = append(cmdArgs, "--output", outputFile)
			}

			if len(compare) == 2 {
				cmdArgs = append(cmdArgs, "--compare", compare[0], compare[1])
			} else if len(compare) > 0 {
				return fmt.Errorf("compare requires exactly 2 variant names")
			}

			if quiet {
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

			if !quiet {
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
			if export != "" && outputFile != "" {
				logger.Info(" Results exported",
					zap.String("file", outputFile),
					zap.String("format", export))
				logger.Info(" Next steps:")
				logger.Info("   - Review exported results for insights")
				logger.Info("   - Consider adjusting prompt weights in /opt/delphi/ab-test-config.json")
				logger.Info("   - Monitor ongoing experiments with: eos delphi services logs prompt-ab-tester")
			}

			return nil
		}),
	}

	cmd.Flags().IntVar(&hours, "hours", 24, "Hours of data to analyze (default: 24)")
	cmd.Flags().StringVar(&export, "export", "", "Export format: json, csv, txt")
	cmd.Flags().StringVar(&outputFile, "output", "", "Output file path for exported results")
	cmd.Flags().StringSliceVar(&compare, "compare", nil, "Compare two specific variants (requires exactly 2 variant names)")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "Suppress console output")

	return cmd
}
