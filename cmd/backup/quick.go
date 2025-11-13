// cmd/backup/quick.go
// Quick directory backup - "just works" for current directory

package backup

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// quickBackupCmd provides instant backup for current directory
var quickBackupCmd = &cobra.Command{
	Use:   ". [directory]",
	Short: "Quick backup of current (or specified) directory",
	Long: `Instantly backup the current directory or specified path with timestamp.

This command reuses your existing backup configuration:
- Uses the default repository defined in /etc/eos/backup.yaml
- Honors repository credentials and password files you already manage
- Timestamps each backup automatically
- Recursive by default

Examples:
  cd /etc && eos backup .                    # Backup /etc
  eos backup . /var/log                      # Backup /var/log
  eos backup . --exclude '*.log'             # Exclude log files
  eos backup . --tag production              # Tag this backup

Restore:
  eos restore . [snapshot-id]                # Restore latest or specific snapshot
  eos restore . --target /tmp/restored       # Restore to different location`,

	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// CRITICAL: Detect flag-like args (P0-1 fix)
		if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
			return err
		}

		// Determine directory to backup
		targetDir := "."
		if len(args) > 0 {
			targetDir = args[0]
		}

		// Get absolute path
		absPath, err := filepath.Abs(targetDir)
		if err != nil {
			return fmt.Errorf("resolving path: %w", err)
		}

		// Get flags
		excludePatterns, _ := cmd.Flags().GetStringSlice("exclude")
		tags, _ := cmd.Flags().GetStringSlice("tag")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		logger.Info("Quick backup initiated",
			zap.String("directory", absPath),
			zap.Strings("exclude", excludePatterns),
			zap.Strings("tags", tags),
			zap.Bool("dry_run", dryRun))

		repoName, repoConfig, err := resolveQuickBackupRepository(rc)
		if err != nil {
			if eos_err.IsExpectedUserError(err) {
				return err
			}
			return err
		}

		logger.Info("Using repository for quick backup",
			zap.String("repository", repoName),
			zap.String("backend", repoConfig.Backend),
			zap.String("url", repoConfig.URL))

		// Create backup client using existing repository configuration
		client, err := backup.NewClient(rc, repoName)
		if err != nil {
			return fmt.Errorf("creating backup client: %w", err)
		}

		// Build restic backup args
		args = []string{"backup", absPath}

		// Add exclusions
		for _, pattern := range excludePatterns {
			args = append(args, "--exclude", pattern)
		}

		// Add tags (including auto-generated timestamp tag)
		timestamp := time.Now().Format("2006-01-02_15:04:05")
		args = append(args, "--tag", "quick-backup")
		args = append(args, "--tag", fmt.Sprintf("timestamp:%s", timestamp))
		for _, tag := range tags {
			args = append(args, "--tag", tag)
		}

		if dryRun {
			args = append(args, "--dry-run")
		}

		// Execute backup
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Backing up: %s", absPath)))

		output, err := client.RunRestic(args...)
		if err != nil {
			if errors.Is(err, backup.ErrResticNotInstalled) {
				logger.Info("terminal prompt:", zap.String("output",
					"Restic is not installed. Install restic (e.g., sudo apt-get install restic) and rerun eos backup ."))
				userErr := eos_err.DependencyError("restic", "run quick backup", err)
				return eos_err.NewExpectedError(rc.Ctx, userErr)
			}

			if errors.Is(err, backup.ErrRepositoryNotInitialized) {
				logger.Info("terminal prompt:", zap.String("output",
					"Restic repository is not initialized. Initialize it (e.g., eos backup create repository local --path /var/lib/eos/backups) and rerun the command."))
				return eos_err.NewExpectedError(rc.Ctx, err)
			}

			logger.Error("Backup failed", zap.Error(err), zap.String("output", string(output)))
			return fmt.Errorf("backup failed: %w", err)
		}

		logger.Info("terminal prompt:", zap.String("output", string(output)))
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("\n✓ Backup complete: %s", absPath)))
		logger.Info("terminal prompt:", zap.String("output",
			fmt.Sprintf("Repository: %s (%s)", repoName, repoConfig.URL)))
		logger.Info("terminal prompt:", zap.String("output", "Restore: eos restore ."))

		return nil
	}),
}

func resolveQuickBackupRepository(rc *eos_io.RuntimeContext) (string, backup.Repository, error) {
	logger := otelzap.Ctx(rc.Ctx)

	config, err := backup.LoadConfig(rc)
	if err != nil {
		return "", backup.Repository{}, fmt.Errorf("loading backup configuration: %w", err)
	}

	repoName := strings.TrimSpace(config.DefaultRepository)
	if repoName != "" {
		if _, ok := config.Repositories[repoName]; !ok {
			return "", backup.Repository{}, fmt.Errorf("default repository %q not found in configuration", repoName)
		}
		repo := config.Repositories[repoName]
		logger.Info("Using default repository for quick backup",
			zap.String("repository", repoName))
		return repoName, repo, nil
	}

	if _, ok := config.Repositories[backup.QuickBackupRepositoryName]; ok {
		repo := config.Repositories[backup.QuickBackupRepositoryName]
		logger.Info("Using quick backup repository from configuration",
			zap.String("repository", backup.QuickBackupRepositoryName))
		return backup.QuickBackupRepositoryName, repo, nil
	}

	if len(config.Repositories) == 0 {
		return "", backup.Repository{}, fmt.Errorf("no repositories configured; add at least one in /etc/eos/backup.yaml")
	}

	if len(config.Repositories) == 1 {
		for name := range config.Repositories {
			repo := config.Repositories[name]
			logger.Info("Using sole configured repository for quick backup",
				zap.String("repository", name))
			return name, repo, nil
		}
	}

	repoNames := make([]string, 0, len(config.Repositories))
	for name := range config.Repositories {
		repoNames = append(repoNames, name)
	}
	sort.Strings(repoNames)

	return "", backup.Repository{}, eos_err.NewExpectedError(rc.Ctx, fmt.Errorf(
		"multiple repositories configured (%s) but no default_repository set; update /etc/eos/backup.yaml to select one",
		strings.Join(repoNames, ", ")))
}

func init() {
	// Add as top-level backup subcommand for quick access
	BackupCmd.AddCommand(quickBackupCmd)

	// Flags
	quickBackupCmd.Flags().StringSliceP("exclude", "e", nil, "Exclude patterns (can specify multiple)")
	quickBackupCmd.Flags().StringSliceP("tag", "t", nil, "Add tags to backup (can specify multiple)")
	quickBackupCmd.Flags().Bool("dry-run", false, "Show what would be backed up without creating backup")
}
