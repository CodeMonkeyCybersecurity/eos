// cmd/backup/quick.go
// Quick directory backup - "just works" for current directory

package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// quickBackupCmd provides instant backup for current directory
var quickBackupCmd = &cobra.Command{
	Use:   ". [directory]",
	Short: "Quick backup of current (or specified) directory",
	Long: `Instantly backup the current directory or specified path with timestamp.

This command "just works" - no configuration needed:
- Auto-creates local repository at ~/.eos/quick-backups
- Auto-generates secure password (stored in Vault or local file)
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

		// Ensure quick backup repository exists
		if err := ensureQuickBackupRepo(rc); err != nil {
			return fmt.Errorf("initializing quick backup repository: %w", err)
		}

		// Create backup client
		client, err := backup.NewClient(rc, "quick-backups")
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
			logger.Error("Backup failed", zap.Error(err), zap.String("output", string(output)))
			return fmt.Errorf("backup failed: %w", err)
		}

		logger.Info("terminal prompt:", zap.String("output", string(output)))
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("\n✓ Backup complete: %s", absPath)))
		logger.Info("terminal prompt:", zap.String("output", "Repository: ~/.eos/quick-backups"))
		logger.Info("terminal prompt:", zap.String("output", "Restore: eos restore ."))

		return nil
	}),
}

// ensureQuickBackupRepo creates the quick backup repository if it doesn't exist
func ensureQuickBackupRepo(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	config, err := backup.LoadConfig(rc)
	if err != nil {
		config = &backup.Config{
			Repositories: make(map[string]backup.Repository),
			Profiles:     make(map[string]backup.Profile),
		}
	}

	repoName := backup.QuickBackupRepositoryName
	repoConfig, exists := config.Repositories[repoName]

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("getting home directory: %w", err)
	}

	defaultRepoPath := filepath.Join(homeDir, backup.QuickBackupRelativePath)

	if repoConfig.URL == "" {
		repoConfig.URL = defaultRepoPath
	}
	if repoConfig.Backend == "" {
		repoConfig.Backend = "local"
	}
	if repoConfig.Name == "" {
		repoConfig.Name = repoName
	}

	if err := os.MkdirAll(repoConfig.URL, 0700); err != nil {
		return fmt.Errorf("creating repository directory: %w", err)
	}

	if _, err := ensureQuickBackupPassword(rc, repoConfig.URL); err != nil {
		return fmt.Errorf("ensuring password: %w", err)
	}

	config.Repositories[repoName] = repoConfig
	config.DefaultRepository = repoName

	if err := backup.SaveConfig(rc, config); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	client, err := backup.NewClient(rc, repoName)
	if err != nil {
		return fmt.Errorf("creating backup client: %w", err)
	}

	configPath := filepath.Join(repoConfig.URL, "config")
	_, statErr := os.Stat(configPath)

	if err := client.InitRepository(); err != nil {
		if errors.Is(err, backup.ErrResticNotInstalled) {
			logger.Info("terminal prompt:", zap.String("output",
				"Restic is not installed. Install restic (e.g., sudo apt-get install restic) and rerun eos backup ."))
		}
		return err
	}

	if !exists || os.IsNotExist(statErr) {
		logger.Info("terminal prompt:", zap.String("output", "✓ Quick backup repository created at ~/.eos/quick-backups"))
	}
	return nil
}

// ensureQuickBackupPassword retrieves or generates the password for quick backups.
func ensureQuickBackupPassword(rc *eos_io.RuntimeContext, repoPath string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	passwordFile := filepath.Join(repoPath, ".password")
	if data, err := os.ReadFile(passwordFile); err == nil {
		password := strings.TrimSpace(string(data))
		if password != "" {
			return password, nil
		}
		logger.Warn("Quick backup password file is empty, generating new password",
			zap.String("path", passwordFile))
	}

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://localhost:8200"
	}
	// TODO: Implement Vault password storage for quick backups once client supports WriteKV.
	_, _ = vault.NewClient(vaultAddr, logger.Logger().Logger)

	password, err := crypto.GeneratePassword(backup.QuickBackupPasswordLength)
	if err != nil {
		return "", fmt.Errorf("generating password: %w", err)
	}

	if err := os.WriteFile(passwordFile, []byte(password), 0600); err != nil {
		return "", fmt.Errorf("writing password file: %w", err)
	}

	logger.Info("Password stored in local file",
		zap.String("path", passwordFile))

	return password, nil
}

func init() {
	// Add as top-level backup subcommand for quick access
	BackupCmd.AddCommand(quickBackupCmd)

	// Flags
	quickBackupCmd.Flags().StringSliceP("exclude", "e", nil, "Exclude patterns (can specify multiple)")
	quickBackupCmd.Flags().StringSliceP("tag", "t", nil, "Add tags to backup (can specify multiple)")
	quickBackupCmd.Flags().Bool("dry-run", false, "Show what would be backed up without creating backup")
}
