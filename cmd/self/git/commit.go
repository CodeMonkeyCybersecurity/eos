package git

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git_management"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var CommitCmd = &cobra.Command{
	Use:     "commit",
	Aliases: []string{"ci"},
	Short:   "Commit changes and optionally push",
	Long: `Commit changes to the Git repository and optionally push to remote.

This command provides automated commit and push functionality:
- Add all files before committing (--add-all)
- Interactive commit message entry
- Automatic push after commit
- Force push option
- Configurable remote and branch

Examples:
  eos git commit --message "Fix bug"              # Simple commit
  eos git commit --add-all --push --message "Update" # Add all, commit, and push
  eos git commit --interactive                     # Interactive mode
  eos git commit --message "Fix" --force --push   # Force push after commit`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		message, _ := cmd.Flags().GetString("message")
		addAll, _ := cmd.Flags().GetBool("add-all")
		push, _ := cmd.Flags().GetBool("push")
		remote, _ := cmd.Flags().GetString("remote")
		branch, _ := cmd.Flags().GetString("branch")
		force, _ := cmd.Flags().GetBool("force")
		interactive, _ := cmd.Flags().GetBool("interactive")
		path, _ := cmd.Flags().GetString("path")
		logger := otelzap.Ctx(rc.Ctx)

		if path == "" {
			var err error
			path, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current directory: %w", err)
			}
		}

		manager := git_management.NewGitManager()

		if !manager.IsGitRepository(rc, path) {
			return fmt.Errorf("not a git repository: %s", path)
		}

		// Interactive mode
		if interactive {
			return runInteractiveCommit(rc, manager, path)
		}

		// Validate commit message
		if message == "" {
			return fmt.Errorf("commit message is required (use --message or --interactive)")
		}

		// Build commit options
		options := &git_management.GitCommitOptions{
			Message:     message,
			AddAll:      addAll,
			Push:        push,
			Remote:      remote,
			Branch:      branch,
			Force:       force,
			Interactive: interactive,
		}

		logger.Info("Committing changes",
			zap.String("path", path),
			zap.String("message", message),
			zap.Bool("add_all", addAll),
			zap.Bool("push", push))

		return manager.CommitAndPush(rc, path, options)
	}),
}

func init() {
	CommitCmd.Flags().StringP("message", "m", "", "Commit message")
	CommitCmd.Flags().BoolP("add-all", "a", false, "Add all files before committing")
	CommitCmd.Flags().BoolP("push", "p", false, "Push after committing")
	CommitCmd.Flags().String("remote", "origin", "Remote name for push")
	CommitCmd.Flags().String("branch", "", "Branch name for push (default: current branch)")
	CommitCmd.Flags().BoolP("force", "f", false, "Force push")
	CommitCmd.Flags().BoolP("interactive", "i", false, "Interactive mode")
	CommitCmd.Flags().String("path", "", "Path to Git repository (default: current directory)")
}

// TODO: HELPER_REFACTOR - Move to pkg/git_management/interactive or pkg/cli/interactive
// Type: Business Logic
// Related functions: None visible in this file
// Dependencies: eos_io, git_management, otelzap, fmt, zap
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func runInteractiveCommit(rc *eos_io.RuntimeContext, manager *git_management.GitManager, path string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: Interactive Git Commit")
	logger.Info("terminal prompt: =====================\n")

	// Show current status
	status, err := manager.GetStatus(rc, path)
	if err != nil {
		logger.Warn("Could not get repository status", zap.Error(err))
	} else {
		logger.Info("terminal prompt: Repository Status:")
		logger.Info(fmt.Sprintf("terminal prompt: - Staged files: %d", len(status.Staged)))
		logger.Info(fmt.Sprintf("terminal prompt: - Modified files: %d", len(status.Modified)))
		logger.Info(fmt.Sprintf("terminal prompt: - Untracked files: %d", len(status.Untracked)))
		logger.Info("terminal prompt: \n")
	}

	// Ask if user wants to add all files
	var addAll bool
	if status != nil && (len(status.Modified) > 0 || len(status.Untracked) > 0) {
		logger.Info("terminal prompt: Add all modified and untracked files? [Y/n]: ")
		var response string
		if _, err := fmt.Scanln(&response); err != nil {
			logger.Info(fmt.Sprintf("terminal prompt: Warning: Failed to read input, using default: %v", err))
		}
		addAll = response != "n" && response != "N"
	}

	// Get commit message
	logger.Info("terminal prompt: Enter commit message: ")
	var message string
	if _, err := fmt.Scanln(&message); err != nil {
		logger.Info(fmt.Sprintf("terminal prompt: Warning: Failed to read commit message: %v", err))
		return fmt.Errorf("failed to read commit message: %w", err)
	}
	if message == "" {
		return fmt.Errorf("commit message cannot be empty")
	}

	// Ask about pushing
	logger.Info("terminal prompt: Push after commit? [y/N]: ")
	var pushResponse string
	if _, err := fmt.Scanln(&pushResponse); err != nil {
		logger.Info(fmt.Sprintf("terminal prompt: Warning: Failed to read push input, using default: %v", err))
	}
	push := pushResponse == "y" || pushResponse == "Y"

	var force bool
	if push {
		logger.Info("terminal prompt: Force push? [y/N]: ")
		var forceResponse string
		fmt.Scanln(&forceResponse)
		force = forceResponse == "y" || forceResponse == "Y"
	}

	// Build commit options
	options := &git_management.GitCommitOptions{
		Message: message,
		AddAll:  addAll,
		Push:    push,
		Remote:  "origin",
		Branch:  "",
		Force:   force,
	}

	logger.Info("Executing interactive commit",
		zap.String("message", message),
		zap.Bool("add_all", addAll),
		zap.Bool("push", push),
		zap.Bool("force", force))

	return manager.CommitAndPush(rc, path, options)
}
