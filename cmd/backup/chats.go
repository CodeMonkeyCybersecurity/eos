// cmd/backup/chats.go
// Command orchestration for AI chat data backup.
// Business logic lives in pkg/chats/.

package backup

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/chats"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var chatsCmd = &cobra.Command{
	Use:   "chats",
	Short: "Back up AI coding assistant chat data for analysis",
	Long: `Back up conversation history from AI coding assistants to a restic repository.

Automatically discovers data from supported tools:
  - Claude Code (~/.claude/)
  - OpenAI Codex (~/.codex/)
  - Windsurf/Codeium (~/.codeium/)
  - Cursor (~/.cursor/)
  - Continue.dev (~/.continue/)
  - GitHub Copilot (~/.config/github-copilot/)
  - Gemini (~/.gemini/)
  - Aider (~/.aider/)

Data is backed up with tags for easy filtering and restore.
Requires an existing restic repository (see: eos backup create repository).

Examples:
  # Back up all discovered chat data
  eos backup chats

  # Dry run to see what would be backed up
  eos backup chats --dry-run

  # Back up only specific tools
  eos backup chats --tool claude-code --tool codex

  # Back up a specific user's data
  eos backup chats --user henry

  # List chat backup snapshots
  eos backup list snapshots --tag chat-backup`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Parse flags
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		targetUser, _ := cmd.Flags().GetString("user")
		toolFilter, _ := cmd.Flags().GetStringSlice("tool")

		// Resolve repository
		repoName, repoConfig, err := resolveChatsBackupRepository(rc)
		if err != nil {
			return err
		}

		logger.Info("Using repository for chat backup",
			zap.String("repository", repoName),
			zap.String("backend", repoConfig.Backend),
			zap.String("url", repoConfig.URL))

		// Delegate to pkg/chats business logic
		config := &chats.BackupConfig{
			RepoName: repoName,
			User:     targetUser,
			Tools:    toolFilter,
			DryRun:   dryRun,
		}

		result, err := chats.RunBackup(rc, config)
		if err != nil {
			if errors.Is(err, backup.ErrResticNotInstalled) {
				logger.Info("terminal prompt:", zap.String("output",
					"Restic is not installed. Install with: sudo apt-get install restic"))
				return eos_err.NewExpectedError(rc.Ctx, eos_err.DependencyError("restic", "back up chat data", err))
			}
			if errors.Is(err, backup.ErrRepositoryNotInitialized) {
				logger.Info("terminal prompt:", zap.String("output",
					"Restic repository not initialized. Create one with:\n"+
						"  eos backup create repository local --path /var/lib/eos/backups"))
				return eos_err.NewExpectedError(rc.Ctx, err)
			}
			return err
		}

		// Report results
		logger.Info("terminal prompt:", zap.String("output", string(result.Output)))

		action := "Backed up"
		if dryRun {
			action = "Would back up"
		}
		logger.Info("terminal prompt:", zap.String("output",
			fmt.Sprintf("\n%s chat data from: %s", action, strings.Join(result.ToolsBacked, ", "))))
		logger.Info("terminal prompt:", zap.String("output",
			fmt.Sprintf("Repository: %s (%s)", repoName, repoConfig.URL)))
		logger.Info("terminal prompt:", zap.String("output",
			fmt.Sprintf("Duration: %s", result.Duration.Round(time.Millisecond))))
		logger.Info("terminal prompt:", zap.String("output",
			"Restore: eos backup restore <snapshot-id> --target /tmp/chats"))
		logger.Info("terminal prompt:", zap.String("output",
			"List:    eos backup list snapshots --tag chat-backup"))

		return nil
	}),
}

// resolveChatsBackupRepository finds a repository to use for chat backups.
// Reuses the same resolution logic as quick backups.
func resolveChatsBackupRepository(rc *eos_io.RuntimeContext) (string, backup.Repository, error) {
	logger := otelzap.Ctx(rc.Ctx)

	config, err := backup.LoadConfig(rc)
	if err != nil {
		return "", backup.Repository{}, fmt.Errorf("loading backup configuration: %w\n"+
			"Create a repository first: eos backup create repository local --path /var/lib/eos/backups", err)
	}

	// Try default repository
	if repoName, err := backup.ResolveRepositoryNameFromConfig(config, ""); err == nil {
		repo := config.Repositories[repoName]
		logger.Info("Using default repository for chat backup",
			zap.String("repository", repoName))
		return repoName, repo, nil
	}

	// If only one repository exists, use it
	if len(config.Repositories) == 1 {
		for name := range config.Repositories {
			repo := config.Repositories[name]
			logger.Info("Using sole configured repository for chat backup",
				zap.String("repository", name))
			return name, repo, nil
		}
	}

	if len(config.Repositories) == 0 {
		return "", backup.Repository{}, fmt.Errorf("no repositories configured\n" +
			"Create one first: eos backup create repository local --path /var/lib/eos/backups")
	}

	// Multiple repos, no default
	repoNames := make([]string, 0, len(config.Repositories))
	for name := range config.Repositories {
		repoNames = append(repoNames, name)
	}
	return "", backup.Repository{}, eos_err.NewExpectedError(rc.Ctx, fmt.Errorf(
		"multiple repositories configured (%s) but no default set; update %s",
		strings.Join(repoNames, ", "), backup.ConfigFile))
}

func init() {
	BackupCmd.AddCommand(chatsCmd)

	chatsCmd.Flags().Bool("dry-run", false, "Show what would be backed up without creating backup")
	chatsCmd.Flags().String("user", "", "Target user (default: auto-detect from SUDO_USER)")
	chatsCmd.Flags().StringSlice("tool", nil,
		fmt.Sprintf("Limit to specific tools (available: %s)", strings.Join(chats.AvailableToolNames(), ", ")))
}
