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
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// fileBackupCmd is the file backup subcommand
var (
	fileBackupBackupDir     string
	fileBackupCustomName    string
	fileBackupInteractive   bool
	fileBackupForce         bool
	fileBackupDryRun        bool
	fileBackupNoVerify      bool
	fileBackupNoPreserve    bool
	fileBackupCreateSymlink bool
	fileBackupOutputJSON    bool
)

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

		logger.Info("Creating file backup",
			zap.String("file", filePath),
			zap.String("backup_dir", fileBackupBackupDir),
			zap.Bool("dry_run", fileBackupDryRun))

		config := file_backup.DefaultFileBackupConfig()
		if fileBackupBackupDir != "" {
			config.DefaultBackupDir = fileBackupBackupDir
		}
		config.VerifyAfterBackup = !fileBackupNoVerify
		config.PreservePermissions = !fileBackupNoPreserve
		config.CreateSymlinks = fileBackupCreateSymlink

		options := &file_backup.BackupOptions{
			BackupDir:           fileBackupBackupDir,
			CustomName:          fileBackupCustomName,
			Interactive:         fileBackupInteractive,
			Force:               fileBackupForce,
			DryRun:              fileBackupDryRun,
			VerifyAfterBackup:   !fileBackupNoVerify,
			PreservePermissions: !fileBackupNoPreserve,
			CreateSymlink:       fileBackupCreateSymlink,
		}

		manager := file_backup.NewFileBackupManager(config)
		result, err := manager.BackupFile(rc, filePath, options)
		if err != nil {
			logger.Error("File backup failed", zap.Error(err))
			return err
		}

		if fileBackupOutputJSON {
			return file_backup.OutputFileBackupJSON(result)
		}

		return file_backup.OutputFileBackupText(result)
	}),
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// fileListCmd is the file list subcommand
var (
	fileListBackupDir  string
	fileListOutputJSON bool
)

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

		logger.Info("Listing file backups", zap.String("backup_dir", fileListBackupDir))

		manager := file_backup.NewFileBackupManager(nil)
		result, err := manager.ListBackups(rc, fileListBackupDir)
		if err != nil {
			logger.Error("Failed to list backups", zap.Error(err))
			return err
		}

		if fileListOutputJSON {
			return file_backup.OutputFileListJSON(result)
		}

		return file_backup.OutputFileListText(result)
	}),
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// fileRestoreCmd is the file restore subcommand
var (
	fileRestoreForce      bool
	fileRestoreDryRun     bool
	fileRestoreOutputJSON bool
)

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
			zap.Bool("dry_run", fileRestoreDryRun))

		manager := file_backup.NewFileBackupManager(nil)
		result, err := manager.RestoreFile(rc, backupPath, restorePath, fileRestoreForce, fileRestoreDryRun)
		if err != nil {
			logger.Error("File restore failed", zap.Error(err))
			return err
		}

		if fileRestoreOutputJSON {
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
	fileBackupCmd.Flags().StringVar(&fileBackupBackupDir, "backup-dir", "", "Directory to store backups (default: /tmp/eos-file-backups)")
	fileBackupCmd.Flags().StringVar(&fileBackupCustomName, "name", "", "Custom name for backup file")
	fileBackupCmd.Flags().BoolVarP(&fileBackupInteractive, "interactive", "i", false, "Prompt for confirmation before backup")
	fileBackupCmd.Flags().BoolVarP(&fileBackupForce, "force", "f", false, "Overwrite existing backup")
	fileBackupCmd.Flags().BoolVar(&fileBackupDryRun, "dry-run", false, "Show what would be done without making changes")
	fileBackupCmd.Flags().BoolVar(&fileBackupNoVerify, "no-verify", false, "Skip backup verification")
	fileBackupCmd.Flags().BoolVar(&fileBackupNoPreserve, "no-preserve-permissions", false, "Don't preserve file permissions")
	fileBackupCmd.Flags().BoolVar(&fileBackupCreateSymlink, "symlink", false, "Create a symlink to latest backup")
	fileBackupCmd.Flags().BoolVar(&fileBackupOutputJSON, "json", false, "Output in JSON format")

	// fileListCmd flags
	fileListCmd.Flags().StringVar(&fileListBackupDir, "backup-dir", "", "Directory to search for backups (default: /tmp/eos-file-backups)")
	fileListCmd.Flags().BoolVar(&fileListOutputJSON, "json", false, "Output in JSON format")

	// fileRestoreCmd flags
	fileRestoreCmd.Flags().BoolVarP(&fileRestoreForce, "force", "f", false, "Overwrite existing file")
	fileRestoreCmd.Flags().BoolVar(&fileRestoreDryRun, "dry-run", false, "Show what would be done without making changes")
	fileRestoreCmd.Flags().BoolVar(&fileRestoreOutputJSON, "json", false, "Output in JSON format")
}
