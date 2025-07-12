package backup

import (
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup/file_backup"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// fileCmd is the file backup command
var fileCmd = &cobra.Command{
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

var fileBackupCmd = &cobra.Command{
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

		// Get flags
		backupDir, _ := cmd.Flags().GetString("backup-dir")
		customName, _ := cmd.Flags().GetString("name")
		interactive, _ := cmd.Flags().GetBool("interactive")
		force, _ := cmd.Flags().GetBool("force")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		noVerify, _ := cmd.Flags().GetBool("no-verify")
		noPreserve, _ := cmd.Flags().GetBool("no-preserve-permissions")
		createSymlink, _ := cmd.Flags().GetBool("symlink")
		outputJSON, _ := cmd.Flags().GetBool("json")

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
			return file_backup.OutputFileBackupJSON(result)
		}

		return file_backup.OutputFileBackupText(result)
	}),
}

var fileListCmd = &cobra.Command{
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

		// Get flags
		backupDir, _ := cmd.Flags().GetString("backup-dir")
		outputJSON, _ := cmd.Flags().GetBool("json")

		logger.Info("Listing file backups", zap.String("backup_dir", backupDir))

		manager := file_backup.NewFileBackupManager(nil)
		result, err := manager.ListBackups(rc, backupDir)
		if err != nil {
			logger.Error("Failed to list backups", zap.Error(err))
			return err
		}

		if outputJSON {
			return file_backup.OutputFileListJSON(result)
		}

		return file_backup.OutputFileListText(result)
	}),
}

var fileRestoreCmd = &cobra.Command{
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

		// Get flags
		force, _ := cmd.Flags().GetBool("force")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		outputJSON, _ := cmd.Flags().GetBool("json")

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
			return file_backup.OutputFileRestoreJSON(result)
		}

		return file_backup.OutputFileRestoreText(result)
	}),
}

func init() {
	// Add subcommands
	fileCmd.AddCommand(fileBackupCmd)
	fileCmd.AddCommand(fileListCmd)
	fileCmd.AddCommand(fileRestoreCmd)

	// fileBackupCmd flags
	fileBackupCmd.Flags().String("backup-dir", "", "Directory to store backups (default: /tmp/eos-file-backups)")
	fileBackupCmd.Flags().String("name", "", "Custom name for backup file")
	fileBackupCmd.Flags().BoolP("interactive", "i", false, "Prompt for confirmation before backup")
	fileBackupCmd.Flags().BoolP("force", "f", false, "Overwrite existing backup")
	fileBackupCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	fileBackupCmd.Flags().Bool("no-verify", false, "Skip backup verification")
	fileBackupCmd.Flags().Bool("no-preserve-permissions", false, "Don't preserve file permissions")
	fileBackupCmd.Flags().Bool("symlink", false, "Create a symlink to latest backup")
	fileBackupCmd.Flags().Bool("json", false, "Output in JSON format")

	// fileListCmd flags
	fileListCmd.Flags().String("backup-dir", "", "Directory to search for backups (default: /tmp/eos-file-backups)")
	fileListCmd.Flags().Bool("json", false, "Output in JSON format")

	// fileRestoreCmd flags
	fileRestoreCmd.Flags().BoolP("force", "f", false, "Overwrite existing file")
	fileRestoreCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	fileRestoreCmd.Flags().Bool("json", false, "Output in JSON format")
}

// All helper functions have been migrated to pkg/backup/file_backup/
