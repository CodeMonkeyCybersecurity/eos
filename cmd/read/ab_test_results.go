// cmd/read/ab_test_results.go
package read

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var abTestResultsCmd = &cobra.Command{
	Use:     "ab-test-results",
	Aliases: []string{"ab-results", "prompt-ab-results"},
	Short:   "Read and analyze A/B testing results for prompt optimization",
	Long: `Read and analyze A/B testing results from the prompt-ab-tester service to evaluate prompt effectiveness.

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
  eos read ab-test-results
  eos read ab-test-results --hours 168 --export csv
  eos read ab-test-results --compare cybersobar delphi_notify_long
  eos read ab-test-results --export json --output /tmp/ab-results.json`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		hours, _ := cmd.Flags().GetInt("hours")
		export, _ := cmd.Flags().GetString("export")
		outputFile, _ := cmd.Flags().GetString("output")
		compare, _ := cmd.Flags().GetStringSlice("compare")
		quiet, _ := cmd.Flags().GetBool("quiet")

		logger.Info("Reading A/B testing results",
			zap.Int("hours_back", hours),
			zap.String("export_format", export),
			zap.Bool("quiet", quiet))

		// Verify analyzer script exists
		analyzerScript := "/usr/local/bin/ab-test-analyzer.py"
		if _, err := os.Stat(analyzerScript); err != nil {
			return fmt.Errorf("A/B testing analyzer not found: %s (deploy with: eos create delphi-services prompt-ab-tester)", analyzerScript)
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

		logger.Info("Running A/B testing analysis",
			zap.String("analyzer", analyzerScript),
			zap.Strings("arguments", cmdArgs[1:]))

		// Execute analyzer
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "python3",
			Args:    cmdArgs,
		})

		if err != nil {
			logger.Error("Analysis failed",
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

		logger.Info("A/B testing analysis completed")

		// Show next steps if export was used
		if export != "" && outputFile != "" {
			logger.Info("Results exported",
				zap.String("file", outputFile),
				zap.String("format", export))
			logger.Info("Next steps:")
			logger.Info("   - Review exported results for insights")
			logger.Info("   - Consider adjusting prompt weights in /opt/delphi/ab-test-config.json")
			logger.Info("   - Monitor ongoing experiments with: eos read delphi-services-logs prompt-ab-tester")
		}

		return nil
	}),
}

func init() {
	abTestResultsCmd.Flags().Int("hours", 24, "Hours of data to analyze (default: 24)")
	abTestResultsCmd.Flags().String("export", "", "Export format: json, csv, txt")
	abTestResultsCmd.Flags().String("output", "", "Output file path for exported results")
	abTestResultsCmd.Flags().StringSlice("compare", nil, "Compare two specific variants (requires exactly 2 variant names)")
	abTestResultsCmd.Flags().Bool("quiet", false, "Suppress console output")

	ReadCmd.AddCommand(abTestResultsCmd)
}
