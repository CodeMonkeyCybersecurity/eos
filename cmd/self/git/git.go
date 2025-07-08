// cmd/git/git.go
package git

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// GitCmd is the root command for Git operations
var GitCmd = &cobra.Command{
	Use:   "git",
	Short: "Git repository management and automation",
	Long: `Comprehensive Git repository management and automation tools.

This command provides enhanced Git functionality including:
- Repository initialization and configuration
- Remote management 
- Automated commit and push workflows
- Deployment automation
- Status and information retrieval

Examples:
  eos git status                     # Get repository status
  eos git config --global           # Configure Git globally
  eos git init --remote-url URL     # Initialize with remote
  eos git commit --message "msg"    # Commit and optionally push
  eos git remote set-url origin URL # Change remote URL`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for git command")
		_ = cmd.Help()
		return nil
	}),
}

func init() {
	// Add subcommands
	GitCmd.AddCommand(newStatusCmd())
	GitCmd.AddCommand(newConfigCmd())
	GitCmd.AddCommand(newInitCmd())
	GitCmd.AddCommand(newCommitCmd())
	GitCmd.AddCommand(newRemoteCmd())
	GitCmd.AddCommand(newDeployCmd())
	GitCmd.AddCommand(newInfoCmd())
}