package test

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TestCmd represents the parent "test" command.
var TestCmd = &cobra.Command{
	Use:   "test",
	Short: "Manage testing infrastructure and validate test health",
	Long: `Testing infrastructure management commands for Eos.

These commands help developers:
- Set up testing infrastructure (pre-commit hooks, coverage tools)
- Validate test health (detect flakiness, check coverage)
- Generate test reports and metrics
- Prevent common testing anti-patterns

Examples:
  # Set up testing infrastructure for new developers
  eos self test setup

  # Validate testing infrastructure health
  eos self test validate

  # Check test coverage locally
  eos self test coverage

  # Detect flaky tests before committing
  eos self test flakiness --package=./pkg/vault/...
`,
	Aliases: []string{"t"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for test command.", zap.String("command", cmd.Use))
		return cmd.Help()
	}),
}

func init() {
	// Add subcommands for testing infrastructure
	TestCmd.AddCommand(setupCmd)
	TestCmd.AddCommand(validateCmd)
	TestCmd.AddCommand(testCoverageCmd)
	TestCmd.AddCommand(flakinessCmd)
	TestCmd.AddCommand(securityCmd)
	TestCmd.AddCommand(benchmarkCmd)
}
