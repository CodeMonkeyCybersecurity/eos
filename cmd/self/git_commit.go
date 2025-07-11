package self

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git/commit"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git/safety"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var gitCommitCmd = &cobra.Command{
	Use:   "commit",
	Short: "Auto-commit changes with smart commit messages",
	Long: `Automatically commit changes to git with intelligently generated commit messages.

This command provides several safety features:
- Generates meaningful commit messages based on file changes
- Scans for potential secrets and sensitive files
- Shows a summary before committing
- Protects against committing to main/master branches
- Respects .gitignore and excludes common artifacts

Options:
  --force      Skip safety checks and confirmation
  --message    Use custom commit message instead of auto-generated
  --push       Automatically push after successful commit
  --no-verify  Skip pre-commit hooks (dangerous!)

Examples:
  # Auto-commit with generated message
  eos self git commit
  
  # Commit with custom message
  eos self git commit --message "Fix critical bug in auth module"
  
  # Commit and push in one step
  eos self git commit --push
  
  # Force commit (skip safety checks)
  eos self git commit --force --message "Emergency fix"
  
  # Dry run to see what would be committed
  eos self git commit --dry-run`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Parse flags
		force := cmd.Flag("force").Value.String() == "true"
		customMessage := cmd.Flag("message").Value.String()
		autoPush := cmd.Flag("push").Value.String() == "true"
		noVerify := cmd.Flag("no-verify").Value.String() == "true"
		dryRun := cmd.Flag("dry-run").Value.String() == "true"

		logger.Info("Starting auto-commit process",
			zap.Bool("force", force),
			zap.String("custom_message", customMessage),
			zap.Bool("auto_push", autoPush),
			zap.Bool("dry_run", dryRun))

		// Ensure we're in the EOS project root
		if err := git.EnsureInProjectRoot(rc); err != nil {
			return err
		}

		// Check git status
		status, err := git.GetStatus(rc)
		if err != nil {
			return fmt.Errorf("failed to get git status: %w", err)
		}

		if status.IsClean {
			logger.Info("No changes to commit")
			return nil
		}

		// Safety checks
		if !force {
			if err := safety.RunSafetyChecks(rc, status); err != nil {
				return err
			}
		}

		// Generate commit message
		var commitMessage string
		if customMessage != "" {
			commitMessage = customMessage
		} else {
			commitMessage, err = commit.GenerateSmartMessage(rc, status)
			if err != nil {
				return fmt.Errorf("failed to generate commit message: %w", err)
			}
		}

		// Show summary
		if err := git.ShowCommitSummary(rc, status, commitMessage); err != nil {
			return err
		}

		// Confirm if not forced
		if !force && !dryRun {
			if !git.ConfirmCommit(rc) {
				logger.Info("Commit cancelled by user")
				return nil
			}
		}

		if dryRun {
			logger.Info("Dry run complete - no changes made")
			return nil
		}

		// Execute commit
		if err := commit.Execute(rc, commitMessage, noVerify); err != nil {
			return err
		}

		// Auto-push if requested
		if autoPush {
			if err := commit.Push(rc); err != nil {
				logger.Warn("Commit successful but push failed", zap.Error(err))
				return err
			}
		}

		logger.Info("Auto-commit completed successfully")
		return nil
	}),
}

func init() {
	gitCommitCmd.Flags().Bool("force", false, "Skip safety checks and confirmation")
	gitCommitCmd.Flags().StringP("message", "m", "", "Use custom commit message")
	gitCommitCmd.Flags().Bool("push", false, "Automatically push after commit")
	gitCommitCmd.Flags().Bool("no-verify", false, "Skip pre-commit hooks")
	gitCommitCmd.Flags().Bool("dry-run", false, "Show what would be committed without actually committing")
}

// All helper functions have been moved to pkg/git/ packages
