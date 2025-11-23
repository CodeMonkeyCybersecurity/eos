// cmd/backup/authentik.go
package backup

import (
	"os"

	authentikbackup "github.com/CodeMonkeyCybersecurity/eos/pkg/authentik/backup"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// AuthentikCmd represents the 'eos backup authentik' command
var AuthentikCmd = &cobra.Command{
	Use:   "authentik",
	Short: "Backup, restore, and manage Authentik configurations",
	Long: `Comprehensive Authentik backup and restore management.

Subcommands:
  create    Create a new backup (default if no subcommand)
  list      List all available backups
  show      Show details of a specific backup
  restore   Restore configuration from backup (wired up, full implementation in progress)
  validate  Validate backup file integrity (coming soon)

Examples:
  # Create full backup (default action)
  eos backup authentik --url https://auth.example.com --token $TOKEN

  # List all backups
  eos backup authentik list

  # Show latest backup details
  eos backup authentik show --latest

  # Backup with secrets included
  eos backup authentik --include-secrets --url https://auth.example.com`,
	RunE: eos.Wrap(backupAuthentik), // Default action: create backup
}

var authentikListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all Authentik backup files",
	Long: `List all Authentik configuration backups in /mnt/eos-backups/authentik/.

Shows: filename, creation date, size, source URL, and resource counts.

Examples:
  # List all backups
  eos backup authentik list

  # List from custom directory
  eos backup authentik list --dir /custom/backup/path`,
	RunE: eos.Wrap(listAuthentikBackups),
}

var authentikShowCmd = &cobra.Command{
	Use:   "show [backup-file]",
	Short: "Show details of a specific Authentik backup",
	Long: `Display detailed information about an Authentik backup file.

Shows:
  - Backup metadata (creation time, source URL, Authentik version)
  - Resource counts (providers, applications, mappings, etc.)
  - File size and location
  - Suggested restore command

Examples:
  # Show latest backup
  eos backup authentik show --latest

  # Show specific backup
  eos backup authentik show /mnt/eos-backups/authentik/authentik-backup-20251005-123456.yaml`,
	RunE: eos.Wrap(showAuthentikBackup),
}

var authentikRestoreCmd = &cobra.Command{
	Use:   "restore [backup-file]",
	Short: "Restore Authentik configuration from backup",
	Long: `Restore Authentik configuration from a backup file.

Features:
  - Restore to any Authentik instance
  - Selective restore (choose resource types)
  - Conflict resolution (skip/update existing)
  - Dry-run mode for testing
  - Automatic pre-restore backup`,
	Example: `  # Restore latest backup to production
  eos backup authentik restore --latest --url https://auth.example.com --token $TOKEN

  # Dry-run restore from specific backup
  eos backup authentik restore backup.yaml --url https://auth.example.com --dry-run

  # Selective restore (only providers and applications)
  eos backup authentik restore backup.yaml --only-types providers,applications`,
	RunE: eos.Wrap(restoreAuthentikBackup),
}

// AddAuthentikSubcommands registers list, show, restore subcommands to AuthentikCmd
func AddAuthentikSubcommands() {
	// Register subcommands
	AuthentikCmd.AddCommand(authentikListCmd)
	AuthentikCmd.AddCommand(authentikShowCmd)
	AuthentikCmd.AddCommand(authentikRestoreCmd)

	// Flags for list command
	authentikListCmd.Flags().String("dir", "/mnt/eos-backups/authentik", "Backup directory to search")

	// Flags for show command
	authentikShowCmd.Flags().Bool("latest", false, "Show details of latest backup")
	authentikShowCmd.Flags().String("dir", "/mnt/eos-backups/authentik", "Backup directory to search")

	// Flags for restore command
	authentikRestoreCmd.Flags().Bool("latest", false, "Restore from latest backup")
	authentikRestoreCmd.Flags().String("dir", "/mnt/eos-backups/authentik", "Backup directory to search")
	authentikRestoreCmd.Flags().String("url", "", "Target Authentik URL (required)")
	authentikRestoreCmd.Flags().String("token", "", "Target Authentik API token (required)")
	authentikRestoreCmd.Flags().Bool("dry-run", false, "Simulate restore without making changes")
	authentikRestoreCmd.Flags().Bool("skip-existing", false, "Skip resources that already exist")
	authentikRestoreCmd.Flags().Bool("update-existing", true, "Update existing resources (default)")
	authentikRestoreCmd.Flags().StringSlice("only-types", []string{}, "Only restore these types (comma-separated)")
	authentikRestoreCmd.Flags().StringSlice("skip-types", []string{}, "Skip these types (comma-separated)")
	authentikRestoreCmd.Flags().Bool("create-backup", true, "Create pre-restore backup")
	authentikRestoreCmd.Flags().Bool("force", false, "Force restore even with warnings")
}

func init() {
	authentikFlags := AuthentikCmd.Flags()

	// API connection flags
	authentikFlags.String("url", os.Getenv("AUTHENTIK_URL"),
		"Authentik URL (or set AUTHENTIK_URL env var)")
	authentikFlags.String("token", os.Getenv("AUTHENTIK_TOKEN"),
		"API Token (or set AUTHENTIK_TOKEN env var)")

	// Output configuration
	authentikFlags.StringP("output", "o", "",
		"Output file path (default: authentik-backup-TIMESTAMP.yaml)")
	authentikFlags.String("format", "yaml", "Output format: yaml or json")

	// Selective backup options
	authentikFlags.StringSlice("types", nil,
		"Resource types to backup (providers,applications,mappings,flows,stages,groups,policies,certificates,blueprints,outposts,tenants)")
	authentikFlags.StringSlice("apps", nil, "Backup only specific applications by name")
	authentikFlags.StringSlice("providers", nil, "Backup only specific providers by name")

	// Security options
	authentikFlags.Bool("include-secrets", false,
		"Include sensitive data like private keys and secrets")
	authentikFlags.Bool("extract-wazuh", false,
		"Extract only Wazuh/Wazuh SSO specific configuration")

	// Legacy filesystem backup flags (kept for compatibility)
	authentikFlags.Bool("include-media", false, "Include media files (filesystem backup only)")
	authentikFlags.Bool("include-database", false, "Include database dump (filesystem backup only)")
	authentikFlags.StringP("path", "p", "/opt/authentik", "Path to Authentik installation (filesystem backup only)")
}

func backupAuthentik(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// If a subcommand was called, show help
	if len(args) > 0 {
		return cmd.Help()
	}

	// Parse flags into config
	url, _ := cmd.Flags().GetString("url")
	token, _ := cmd.Flags().GetString("token")
	output, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	types, _ := cmd.Flags().GetStringSlice("types")
	apps, _ := cmd.Flags().GetStringSlice("apps")
	providers, _ := cmd.Flags().GetStringSlice("providers")
	includeSecrets, _ := cmd.Flags().GetBool("include-secrets")
	extractWazuh, _ := cmd.Flags().GetBool("extract-wazuh")
	includeMedia, _ := cmd.Flags().GetBool("include-media")
	includeDatabase, _ := cmd.Flags().GetBool("include-database")
	path, _ := cmd.Flags().GetString("path")

	config := &authentikbackup.Config{
		URL:             url,
		Token:           token,
		Output:          output,
		Format:          format,
		Types:           types,
		Apps:            apps,
		Providers:       providers,
		IncludeSecrets:  includeSecrets,
		ExtractWazuh:    extractWazuh,
		IncludeMedia:    includeMedia,
		IncludeDatabase: includeDatabase,
		Path:            path,
	}

	// Check if this is a filesystem backup request (legacy)
	if includeMedia || includeDatabase {
		return authentikbackup.BackupFilesystem(rc, config)
	}

	// Delegate to pkg/
	return authentikbackup.Backup(rc, config)
}

func listAuthentikBackups(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	backupDir, _ := cmd.Flags().GetString("dir")

	config := &authentikbackup.ListConfig{
		BackupDir: backupDir,
	}

	return authentikbackup.List(rc, config)
}

func showAuthentikBackup(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	latest, _ := cmd.Flags().GetBool("latest")
	backupDir, _ := cmd.Flags().GetString("dir")

	var backupFile string
	if len(args) > 0 {
		backupFile = args[0]
	}

	config := &authentikbackup.ShowConfig{
		BackupFile: backupFile,
		Latest:     latest,
		BackupDir:  backupDir,
	}

	return authentikbackup.Show(rc, config)
}

func restoreAuthentikBackup(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	latest, _ := cmd.Flags().GetBool("latest")
	backupDir, _ := cmd.Flags().GetString("dir")
	url, _ := cmd.Flags().GetString("url")
	token, _ := cmd.Flags().GetString("token")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	skipExisting, _ := cmd.Flags().GetBool("skip-existing")
	updateExisting, _ := cmd.Flags().GetBool("update-existing")
	onlyTypes, _ := cmd.Flags().GetStringSlice("only-types")
	skipTypes, _ := cmd.Flags().GetStringSlice("skip-types")
	createBackup, _ := cmd.Flags().GetBool("create-backup")
	force, _ := cmd.Flags().GetBool("force")

	var backupFile string
	if latest {
		var err error
		backupFile, err = authentikbackup.FindLatestBackup(backupDir)
		if err != nil {
			return err
		}
	} else if len(args) > 0 {
		backupFile = args[0]
	}

	config := &authentikbackup.RestoreConfig{
		BackupFile:     backupFile,
		URL:            url,
		Token:          token,
		DryRun:         dryRun,
		SkipExisting:   skipExisting,
		UpdateExisting: updateExisting,
		OnlyTypes:      onlyTypes,
		SkipTypes:      skipTypes,
		CreateBackup:   createBackup,
		Force:          force,
	}

	return authentikbackup.Restore(rc, config)
}
