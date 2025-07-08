package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/file_backup"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// newFileCmd creates the file backup command
func newFileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "file",
		Aliases: []string{"single"},
		Short:   "Simple file backup operations",
		Long: `Simple file backup operations for individual files.

This command provides basic file backup functionality similar to the original 
backupAFile.sh script but with enhanced features and proper integration.

Examples:
  eos backup file create /etc/hosts               # Backup a single file
  eos backup file create /etc/hosts --interactive # Interactive backup with confirmation
  eos backup file list                            # List all file backups
  eos backup file restore backup.txt.backup.Monday_2006-01-02_150405 /tmp/restored.txt`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			otelzap.Ctx(rc.Ctx).Info("No subcommand provided for file backup command")
			_ = cmd.Help()
			return nil
		}),
	}

	// Add subcommands
	cmd.AddCommand(newFileBackupCmd())
	cmd.AddCommand(newFileListCmd())
	cmd.AddCommand(newFileRestoreCmd())

	return cmd
}

// newFileBackupCmd creates the file backup subcommand
func newFileBackupCmd() *cobra.Command {
	var (
		backupDir     string
		customName    string
		interactive   bool
		force         bool
		dryRun        bool
		noVerify      bool
		noPreserve    bool
		createSymlink bool
		outputJSON    bool
	)

	cmd := &cobra.Command{
		Use:     "create <file>",
		Aliases: []string{"backup", "cp"},
		Short:   "Create a backup of a single file",
		Long: `Create a backup of a single file with timestamp.

The backup will be created with a timestamp suffix in the format:
filename.backup.Monday_2006-01-02_150405

Examples:
  eos backup file create /etc/hosts                              # Basic backup
  eos backup file create /etc/hosts --backup-dir /backups       # Custom backup directory
  eos backup file create /etc/hosts --name my-hosts-backup      # Custom backup name
  eos backup file create /etc/hosts --interactive               # Prompt for confirmation
  eos backup file create /etc/hosts --dry-run                   # Show what would be done`,

		Args: cobra.ExactArgs(1),
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			filePath := args[0]

			logger.Info("Creating file backup",
				zap.String("file", filePath),
				zap.String("backup_dir", backupDir),
				zap.Bool("dry_run", dryRun))

			config := file_backup.DefaultFileBackupConfig()
			if backupDir != "" {
				config.DefaultBackupDir = backupDir
			}
			config.VerifyAfterBackup = !noVerify
			config.PreservePermissions = !noPreserve
			config.CreateSymlinks = createSymlink

			options := &file_backup.BackupOptions{
				BackupDir:           backupDir,
				CustomName:          customName,
				Interactive:         interactive,
				Force:               force,
				DryRun:              dryRun,
				VerifyAfterBackup:   !noVerify,
				PreservePermissions: !noPreserve,
				CreateSymlink:       createSymlink,
			}

			manager := file_backup.NewFileBackupManager(config)
			result, err := manager.BackupFile(rc, filePath, options)
			if err != nil {
				logger.Error("File backup failed", zap.Error(err))
				return err
			}

			if outputJSON {
				return outputFileBackupJSON(result)
			}

			return outputFileBackupText(result)
		}),
	}

	cmd.Flags().StringVar(&backupDir, "backup-dir", "", "Directory to store backups (default: /tmp/eos-file-backups)")
	cmd.Flags().StringVar(&customName, "name", "", "Custom name for backup file")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Prompt for confirmation before backup")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing backup")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without making changes")
	cmd.Flags().BoolVar(&noVerify, "no-verify", false, "Skip backup verification")
	cmd.Flags().BoolVar(&noPreserve, "no-preserve-permissions", false, "Don't preserve file permissions")
	cmd.Flags().BoolVar(&createSymlink, "symlink", false, "Create a symlink to latest backup")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}

// newFileListCmd creates the file list subcommand
func newFileListCmd() *cobra.Command {
	var (
		backupDir  string
		outputJSON bool
	)

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all file backups",
		Long: `List all file backups in the backup directory.

Shows backup name, original file, size, and backup time for each backup.

Examples:
  eos backup file list                              # List all backups
  eos backup file list --backup-dir /backups       # List backups in specific directory
  eos backup file list --json                      # Output in JSON format`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			logger.Info("Listing file backups", zap.String("backup_dir", backupDir))

			manager := file_backup.NewFileBackupManager(nil)
			result, err := manager.ListBackups(rc, backupDir)
			if err != nil {
				logger.Error("Failed to list backups", zap.Error(err))
				return err
			}

			if outputJSON {
				return outputFileListJSON(result)
			}

			return outputFileListText(result)
		}),
	}

	cmd.Flags().StringVar(&backupDir, "backup-dir", "", "Directory to search for backups (default: /tmp/eos-file-backups)")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}

// newFileRestoreCmd creates the file restore subcommand
func newFileRestoreCmd() *cobra.Command {
	var (
		force      bool
		dryRun     bool
		outputJSON bool
	)

	cmd := &cobra.Command{
		Use:   "restore <backup-file> [restore-path]",
		Short: "Restore a backup file",
		Long: `Restore a backup file to the original location or a specified path.

If no restore path is provided, the original filename will be used in the current directory.

Examples:
  eos backup file restore hosts.backup.Monday_2006-01-02_150405        # Restore to current directory
  eos backup file restore hosts.backup.Monday_2006-01-02_150405 /etc/hosts  # Restore to specific path
  eos backup file restore hosts.backup.Monday_2006-01-02_150405 --dry-run   # Show what would be done`,

		Args: cobra.RangeArgs(1, 2),
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			backupPath := args[0]

			// Determine restore path
			var restorePath string
			if len(args) > 1 {
				restorePath = args[1]
			} else {
				// Use original filename in current directory
				manager := file_backup.NewFileBackupManager(nil)
				if originalFile, _ := manager.ParseBackupName(backupPath); originalFile != "" {
					restorePath = originalFile
				} else {
					// Fallback: remove .backup.timestamp
					parts := strings.Split(backupPath, ".backup.")
					if len(parts) > 0 {
						restorePath = parts[0]
					} else {
						restorePath = backupPath + ".restored"
					}
				}
			}

			logger.Info("Restoring file backup",
				zap.String("backup_path", backupPath),
				zap.String("restore_path", restorePath),
				zap.Bool("dry_run", dryRun))

			manager := file_backup.NewFileBackupManager(nil)
			result, err := manager.RestoreFile(rc, backupPath, restorePath, force, dryRun)
			if err != nil {
				logger.Error("File restore failed", zap.Error(err))
				return err
			}

			if outputJSON {
				return outputFileRestoreJSON(result)
			}

			return outputFileRestoreText(result)
		}),
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing file")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without making changes")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}

// Output formatting functions

func outputFileBackupJSON(result *file_backup.FileBackupOperation) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputFileBackupText(result *file_backup.FileBackupOperation) error {
	if result.DryRun {
		fmt.Printf("[DRY RUN] %s\n", result.Message)
	} else if result.Success {
		fmt.Printf("✓ %s\n", result.Message)
		if result.Duration > 0 {
			fmt.Printf("  Duration: %v\n", result.Duration)
		}
		if result.FileSize > 0 {
			fmt.Printf("  Size: %d bytes\n", result.FileSize)
		}
	} else {
		fmt.Printf("✗ %s\n", result.Message)
	}
	return nil
}

func outputFileListJSON(result *file_backup.BackupListResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputFileListText(result *file_backup.BackupListResult) error {
	if result.TotalBackups == 0 {
		fmt.Printf("No backups found in %s\n", result.BackupDir)
		return nil
	}

	fmt.Printf("Found %d backups in %s\n", result.TotalBackups, result.BackupDir)
	fmt.Printf("Total size: %d bytes\n\n", result.TotalSize)

	// Print header
	fmt.Printf("%-30s %-20s %-12s %s\n", "BACKUP NAME", "ORIGINAL FILE", "SIZE", "BACKUP TIME")
	fmt.Println(strings.Repeat("-", 80))

	// Print backups
	for _, backup := range result.Backups {
		originalFile := backup.OriginalFile
		if originalFile == "" {
			originalFile = "-"
		}

		backupTime := "-"
		if !backup.BackupTime.IsZero() {
			backupTime = backup.BackupTime.Format("01-02 15:04")
		}

		fmt.Printf("%-30s %-20s %-12d %s\n",
			utils.TruncateString(backup.Name, 30),
			utils.TruncateString(originalFile, 20),
			backup.Size,
			backupTime)
	}

	return nil
}

func outputFileRestoreJSON(result *file_backup.RestoreOperation) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputFileRestoreText(result *file_backup.RestoreOperation) error {
	if result.DryRun {
		fmt.Printf("[DRY RUN] %s\n", result.Message)
	} else if result.Success {
		fmt.Printf("✓ %s\n", result.Message)
		if result.Overwritten {
			fmt.Printf("  (File was overwritten)\n")
		}
		if result.Duration > 0 {
			fmt.Printf("  Duration: %v\n", result.Duration)
		}
	} else {
		fmt.Printf("✗ %s\n", result.Message)
	}
	return nil
}
