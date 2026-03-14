// cmd/backup/chats.go
// Command orchestration for AI chat history backup with SHA-256 deduplication.
//
// Provides: eos backup chats [--dry-run]
//
// Discovers chat histories from AI coding tools (Claude Code, Windsurf, Cursor,
// Codex CLI, Cline, Roo Code, GitHub Copilot, Aider, Amazon Q, Continue.dev),
// deduplicates via SHA-256 manifest, and creates incremental tar.gz archives
// in chats/backups/ relative to the repo root.

package backup

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/chats"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var chatsCmd = &cobra.Command{
	Use:   "chats",
	Short: "Back up AI coding tool chat histories with SHA-256 deduplication",
	Long: `Discovers and archives chat histories from AI coding tools.

Creates incremental tar.gz archives in chats/backups/ relative to the repo root.
Uses SHA-256 manifest-based deduplication — unchanged files are skipped.

Supported tools: Claude Code, Windsurf, Cursor, Codex CLI, Cline,
Roo Code, GitHub Copilot, Aider, Amazon Q, Continue.dev.

Examples:
  eos backup chats            # Discover sources and create incremental backup
  eos backup chats --dry-run  # Preview what would be backed up`,

	RunE: eos.Wrap(runBackupChats),
}

func init() {
	BackupCmd.AddCommand(chatsCmd)
	chatsCmd.Flags().Bool("dry-run", false, "Show what would be backed up without creating archive")
}

// chatBackupFn is the business logic entry point (replaceable for testing).
var chatBackupFn = chats.RunBackup

func runBackupChats(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
		return err
	}

	dryRun, err := cmd.Flags().GetBool("dry-run")
	if err != nil {
		return fmt.Errorf("failed to read --dry-run flag: %w", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to resolve home directory: %w", err)
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("failed to resolve config directory: %w", err)
	}
	repoRoot, err := resolveRepoRoot()
	if err != nil {
		return fmt.Errorf("failed to resolve repo root: %w", err)
	}

	result, err := chatBackupFn(rc, chats.BackupConfig{
		RepoRoot:  repoRoot,
		HomeDir:   homeDir,
		ConfigDir: configDir,
		DryRun:    dryRun,
	})
	if err != nil {
		return fmt.Errorf("chat backup failed: %w", err)
	}

	logger.Info("Chat backup complete",
		zap.Int("sources", result.SourcesFound),
		zap.Int("new", result.NewFiles),
		zap.Int("changed", result.ChangedFiles),
		zap.Int("unchanged", result.UnchangedFiles),
		zap.String("archive", result.ArchivePath))

	return nil
}

// resolveRepoRoot finds the git repository root directory.
func resolveRepoRoot() (string, error) {
	if dir := os.Getenv("CLAUDE_PROJECT_DIR"); dir != "" {
		return dir, nil
	}
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err == nil {
		return strings.TrimSpace(string(out)), nil
	}
	return os.Getwd()
}
