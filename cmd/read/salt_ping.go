// cmd/read/salt_ping.go
package read

import (
	"fmt"
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
		_, _ = cmd.Flags().GetBool("json")
		_, _ = cmd.Flags().GetBool("verbose")

		logger.Info("Starting Salt minion ping",
			zap.String("target", target),
			zap.String("target_type", targetType),
			zap.Duration("timeout", timeout))

		// Salt ping feature temporarily disabled during refactoring
		logger.Warn("Salt ping feature temporarily disabled during refactoring",
			zap.String("target", target))
		return fmt.Errorf("ping method not available in current saltstack.KeyManager interface")
	}),
}

func init() {
	saltPingCmd.Flags().String("target-type", "glob", "Target type: glob, pcre, list, grain, pillar, nodegroup")
	saltPingCmd.Flags().Duration("timeout", 10*time.Second, "Timeout for ping operation")
	saltPingCmd.Flags().Bool("json", false, "Output results in JSON format")
	saltPingCmd.Flags().BoolP("verbose", "v", false, "Verbose output with timing information")

	ReadCmd.AddCommand(saltPingCmd)
}
