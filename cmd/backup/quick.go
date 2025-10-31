// cmd/backup/quick.go
// Quick directory backup - "just works" for current directory

package backup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Repository: ~/.eos/quick-backups")))
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Restore: eos restore .")))

		return nil
	}),
}

// ensureQuickBackupRepo creates the quick backup repository if it doesn't exist
func ensureQuickBackupRepo(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Load config
	config, err := backup.LoadConfig(rc)
	if err != nil {
		// Config doesn't exist yet, create it
		config = &backup.Config{
			Repositories:      make(map[string]backup.Repository),
			Profiles:          make(map[string]backup.Profile),
			DefaultRepository: "quick-backups",
		}
	}

	// Check if quick-backups repo already exists
	if _, exists := config.Repositories["quick-backups"]; exists {
		logger.Debug("Quick backup repository already exists")
		return nil
	}

	// Create repository directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("getting home directory: %w", err)
	}

	repoPath := filepath.Join(homeDir, ".eos", "quick-backups")
	if err := os.MkdirAll(repoPath, 0700); err != nil {
		return fmt.Errorf("creating repository directory: %w", err)
	}

	logger.Info("Creating quick backup repository",
		zap.String("path", repoPath))

	// Generate secure password
	password, err := generateQuickBackupPassword(rc, repoPath)
	if err != nil {
		return fmt.Errorf("generating password: %w", err)
	}

	// Initialize restic repository
	if err := initializeResticRepo(rc, repoPath, password); err != nil {
		return fmt.Errorf("initializing restic repository: %w", err)
	}

	// Add to config
	config.Repositories["quick-backups"] = backup.Repository{
		Name:    "quick-backups",
		Backend: "local",
		URL:     repoPath,
	}

	config.DefaultRepository = "quick-backups"

	// Save config
	if err := backup.SaveConfig(rc, config); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	logger.Info("terminal prompt:", zap.String("output", "✓ Quick backup repository created at ~/.eos/quick-backups"))

	return nil
}

// generateQuickBackupPassword generates and stores password for quick backups
func generateQuickBackupPassword(rc *eos_io.RuntimeContext, repoPath string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Try Vault first
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://localhost:8200"
	}

	// TODO: Fix Vault client API - WriteKV method investigation needed
	// Temporarily disabled pending vault client method fix
	_, _ = vault.NewClient(vaultAddr, logger.Logger().Logger)

	// Fallback to local file
	passwordFile := filepath.Join(repoPath, ".password")
	password, err := crypto.GeneratePassword(32)
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

// initializeResticRepo initializes a new restic repository
func initializeResticRepo(rc *eos_io.RuntimeContext, repoPath, password string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if already initialized
	if _, err := os.Stat(filepath.Join(repoPath, "config")); err == nil {
		logger.Debug("Repository already initialized")
		return nil
	}

	logger.Info("Initializing restic repository", zap.String("path", repoPath))

	// Build init command
	cmd := exec.CommandContext(rc.Ctx, "restic", "init")
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("RESTIC_REPOSITORY=%s", repoPath),
		fmt.Sprintf("RESTIC_PASSWORD=%s", password),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to initialize repository",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("restic init failed: %w\n%s", err, output)
	}

	logger.Info("Repository initialized successfully")
	return nil
}

func init() {
	// Add as top-level backup subcommand for quick access
	BackupCmd.AddCommand(quickBackupCmd)

	// Flags
	quickBackupCmd.Flags().StringSliceP("exclude", "e", nil, "Exclude patterns (can specify multiple)")
	quickBackupCmd.Flags().StringSliceP("tag", "t", nil, "Add tags to backup (can specify multiple)")
	quickBackupCmd.Flags().Bool("dry-run", false, "Show what would be backed up without creating backup")
}
