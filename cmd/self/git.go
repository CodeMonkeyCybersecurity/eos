package self

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var gitCmd = &cobra.Command{
	Use:   "git",
	Short: "Git automation commands",
	Long: `Git automation commands for the EOS project.

Provides intelligent automation for common git operations while maintaining
safety and security standards.`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("No git subcommand provided", zap.String("command", cmd.Use))
		return cmd.Help()
	}),
}

func init() {
	SelfCmd.AddCommand(gitCmd)
	gitCmd.AddCommand(gitCommitCmd)
}