// cmd/read/salt_ping.go
package read

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var saltPingCmd = &cobra.Command{
	Use:     "salt-ping [target]",
	Aliases: []string{"salt-connectivity", "salt-minion-ping"},
	Short:   "Test Salt minion connectivity and responsiveness",
	Long: `Test Salt minion connectivity and responsiveness by sending test.ping.

This command sends a test.ping to the specified minions and reports
which minions are responsive. It's useful for checking minion health
and connectivity before running other Salt operations.

Examples:
  eos read salt-ping '*'                         # Ping all minions
  eos read salt-ping 'web*'                      # Ping web servers
  eos read salt-ping 'web01,web02'               # Ping specific minions (list target type)
  eos read salt-ping 'os:Ubuntu' --target-type grain  # Ping Ubuntu minions via grain
  
Target Types:
  glob     - Shell-style wildcards (default)
  pcre     - Perl-compatible regular expressions
  list     - Comma-separated list of minion IDs
  grain    - Match based on grains data
  pillar   - Match based on pillar data
  nodegroup - Match based on nodegroup`,

	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Parse target - default to '*' if not provided
		target := "*"
		if len(args) > 0 {
			target = args[0]
		}

		// Parse flags
		targetType, _ := cmd.Flags().GetString("target-type")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		outputJSON, _ := cmd.Flags().GetBool("json")
		verbose, _ := cmd.Flags().GetBool("verbose")

		logger.Info("Starting Salt minion ping",
			zap.String("target", target),
			zap.String("target_type", targetType),
			zap.Duration("timeout", timeout))

		// Create Salt client
		saltClient := saltstack.NewSaltClient()

		// Create context with timeout
		ctx, cancel := context.WithTimeout(rc.Ctx, timeout)
		defer cancel()

		// Execute ping
		result, err := saltClient.Ping(ctx, target, targetType)
		if err != nil {
			logger.Error("Salt ping failed", zap.Error(err))
			return fmt.Errorf("failed to ping Salt minions: %w", err)
		}

		// Output results
		if outputJSON {
			return outputPingResultsJSON(result)
		}

		return outputPingResultsText(result, target, verbose)
	}),
}

func init() {
	saltPingCmd.Flags().String("target-type", "glob", "Target type: glob, pcre, list, grain, pillar, nodegroup")
	saltPingCmd.Flags().Duration("timeout", 10*time.Second, "Timeout for ping operation")
	saltPingCmd.Flags().Bool("json", false, "Output results in JSON format")
	saltPingCmd.Flags().BoolP("verbose", "v", false, "Verbose output with timing information")

	ReadCmd.AddCommand(saltPingCmd)
}

func outputPingResultsJSON(result map[string]interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputPingResultsText(result map[string]interface{}, target string, verbose bool) error {
	fmt.Printf("Salt Ping Results for target: %s\n", target)
	fmt.Println(strings.Repeat("=", 50))

	var responsive, unresponsive []string

	for minion, response := range result {
		if response == true {
			responsive = append(responsive, minion)
		} else {
			unresponsive = append(unresponsive, minion)
		}
	}

	fmt.Printf("Responsive minions (%d):\n", len(responsive))
	if len(responsive) > 0 {
		for _, minion := range responsive {
			fmt.Printf("  ✓ %s\n", minion)
		}
	} else {
		fmt.Println("  (none)")
	}

	if len(unresponsive) > 0 {
		fmt.Printf("\nUnresponsive minions (%d):\n", len(unresponsive))
		for _, minion := range unresponsive {
			fmt.Printf("  ✗ %s\n", minion)
		}
	}

	fmt.Printf("\nSummary: %d/%d minions responded\n",
		len(responsive), len(responsive)+len(unresponsive))

	if verbose && len(result) > 0 {
		fmt.Println("\nDetailed Response Data:")
		for minion, response := range result {
			fmt.Printf("  %s: %v\n", minion, response)
		}
	}

	return nil
}
