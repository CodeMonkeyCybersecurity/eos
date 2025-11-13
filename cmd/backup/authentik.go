// cmd/backup/authentik.go
package backup

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	consul_config "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/config"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
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

	// Note: AuthentikCmd is registered to BackupCmd in backup.go AddSubcommands()
	// Note: Subcommands (list, show, restore) are registered in AddAuthentikSubcommands()
}

func backupAuthentik(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// If a subcommand was called, this function shouldn't run
	// This is a fallback for the default "create backup" action
	if len(args) > 0 {
		// If user typed something like "eos backup authentik list" but it wasn't recognized,
		// show help
		return cmd.Help()
	}

	// Get flags
	url, _ := cmd.Flags().GetString("url")
	token, _ := cmd.Flags().GetString("token")
	output, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	types, _ := cmd.Flags().GetStringSlice("types")
	apps, _ := cmd.Flags().GetStringSlice("apps")
	providers, _ := cmd.Flags().GetStringSlice("providers")
	includeSecrets, _ := cmd.Flags().GetBool("include-secrets")
	extractWazuh, _ := cmd.Flags().GetBool("extract-wazuh")

	// Check if this is a filesystem backup request (legacy)
	includeMedia, _ := cmd.Flags().GetBool("include-media")
	includeDatabase, _ := cmd.Flags().GetBool("include-database")
	if includeMedia || includeDatabase {
		return backupAuthentikFilesystem(rc, cmd)
	}

	// ASSESS - Validate API parameters
	logger.Info("Starting Authentik configuration backup")

	// Config resolution priority:
	// 1. CLI flag (--url)
	// 2. Environment variable (AUTHENTIK_URL)
	// 3. Consul KV (eos/config/authentik/url)
	// 4. Interactive prompt (with option to save to Consul)

	if url == "" {
		// Try to get from Consul
		if consulClient, err := consul_config.NewClient(rc.Ctx); err == nil {
			if consulURL, found, _ := consulClient.Get(rc.Ctx, "authentik/url"); found && consulURL != "" {
				url = consulURL
				logger.Info("Retrieved Authentik URL from Consul", zap.String("url", url))
			}
		} else {
			logger.Debug("Consul not available for config retrieval", zap.Error(err))
		}
	}

	if url == "" {
		input, err := eos_io.PromptInput(rc, "Enter Authentik URL (e.g., https://auth.example.com): ", "authentik_url")
		if err != nil {
			return err
		}
		url = input

		// Offer to save to Consul for next time
		savePrompt, err := eos_io.PromptInput(rc, "Save Authentik URL to Consul for future use? (y/n): ", "save_to_consul")
		if err == nil && (savePrompt == "y" || savePrompt == "yes" || savePrompt == "Y" || savePrompt == "Yes") {
			if consulClient, err := consul_config.NewClient(rc.Ctx); err == nil {
				if err := consulClient.Set(rc.Ctx, "authentik/url", url); err == nil {
					logger.Info("Saved Authentik URL to Consul - you won't be prompted again")
				} else {
					logger.Warn("Failed to save to Consul", zap.Error(err))
				}
			}
		}
	}

	// Auto-add https:// if no protocol specified
	if url != "" && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
		logger.Info("Added https:// prefix to URL", zap.String("url", url))
	}

	// Note: Token is a secret - ideally should be in Vault, not Consul
	// For now, we'll prompt each time (security best practice)
	// TODO: Integrate with Vault for secure token storage
	if token == "" {
		input, err := eos_io.PromptSecurePassword(rc, "Enter Authentik API token: ")
		if err != nil {
			return err
		}
		token = input
	}

	if url == "" || token == "" {
		return eos_err.NewUserError("Authentik URL and token are required")
	}

	// Determine output file - default to /mnt for centralized backup storage
	if output == "" {
		timestamp := time.Now().Format("20060102-150405")
		backupDir := "/mnt/eos-backups/authentik"

		// Create backup directory if it doesn't exist
		if err := os.MkdirAll(backupDir, shared.ServiceDirPerm); err != nil {
			logger.Warn("Failed to create /mnt backup directory, using current directory",
				zap.Error(err))
			output = fmt.Sprintf("authentik-backup-%s.%s", timestamp, format)
		} else {
			output = filepath.Join(backupDir, fmt.Sprintf("authentik-backup-%s.%s", timestamp, format))
		}
	}

	// Create backup directory if needed
	backupDir := filepath.Dir(output)
	if backupDir != "." && backupDir != "/" {
		if err := os.MkdirAll(backupDir, shared.ServiceDirPerm); err != nil {
			return fmt.Errorf("failed to create backup directory: %w", err)
		}
	}

	// INTERVENE - Extract configuration
	logger.Info("Extracting Authentik configuration",
		zap.String("url", url),
		zap.String("output", output))

	// If extracting Wazuh-specific config
	if extractWazuh {
		types = []string{"providers", "applications", "mappings", "groups"}
		logger.Info("Extracting Wazuh/Wazuh SSO specific configuration")
	}

	// Default to all types if none specified
	if len(types) == 0 && !extractWazuh {
		types = []string{"providers", "applications", "mappings", "flows",
			"stages", "groups", "policies", "certificates", "blueprints", "outposts", "tenants"}
	}

	// Extract configuration using the helper function
	config, err := authentik.ExtractConfigurationAPI(rc.Ctx, url, token, types, apps, providers, includeSecrets)
	if err != nil {
		return fmt.Errorf("failed to extract configuration: %w", err)
	}

	// Save to file
	var data []byte
	if format == "yaml" {
		data, err = yaml.Marshal(config)
	} else {
		data, err = json.MarshalIndent(config, "", "  ")
	}
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(output, data, shared.SecretFilePerm); err != nil {
		return fmt.Errorf("failed to save backup: %w", err)
	}

	// EVALUATE - Verify and report
	logger.Info("Backup completed successfully",
		zap.String("file", output),
		zap.Int("providers", len(config.Providers)),
		zap.Int("applications", len(config.Applications)),
		zap.Int("mappings", len(config.PropertyMappings)),
		zap.Int("flows", len(config.Flows)),
		zap.Int("stages", len(config.Stages)),
		zap.Int("groups", len(config.Groups)),
		zap.Int("policies", len(config.Policies)),
		zap.Int("certificates", len(config.Certificates)),
		zap.Int("blueprints", len(config.Blueprints)),
		zap.Int("outposts", len(config.Outposts)),
		zap.Int("tenants", len(config.Tenants)))

	// Check for critical Wazuh configuration
	if extractWazuh || checkWazuhConfiguration(config) {
		logger.Info("Found Wazuh/Wazuh SSO configuration",
			zap.String("tip", "Use 'eos update authentik --from-backup' to import"))

		// Verify critical Roles mapping
		if !checkRolesMapping(config) {
			logger.Warn("Missing critical 'Roles' property mapping required for Wazuh SSO")
		}
	}

	return nil
}

// backupAuthentikFilesystem handles legacy filesystem-based backups
func backupAuthentikFilesystem(rc *eos_io.RuntimeContext, _ *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn("Filesystem backup mode is deprecated. Consider using API-based backup instead.")

	// TODO: Implement filesystem backup if needed
	return eos_err.NewUserError("Filesystem backup not yet implemented. Use API-based backup with --url and --token flags")
}

// checkWazuhConfiguration checks if the config contains Wazuh/Wazuh related items
func checkWazuhConfiguration(config *authentik.AuthentikConfig) bool {
	keywords := []string{"wazuh", "wazuh", "analyst", "soc", "siem"}

	// Check providers
	for _, provider := range config.Providers {
		lowerName := strings.ToLower(provider.Name)
		for _, keyword := range keywords {
			if strings.Contains(lowerName, keyword) {
				return true
			}
		}
	}

	// Check applications
	for _, app := range config.Applications {
		lowerName := strings.ToLower(app.Name)
		lowerSlug := strings.ToLower(app.Slug)
		for _, keyword := range keywords {
			if strings.Contains(lowerName, keyword) || strings.Contains(lowerSlug, keyword) {
				return true
			}
		}
	}

	// Check groups
	for _, group := range config.Groups {
		lowerName := strings.ToLower(group.Name)
		for _, keyword := range keywords {
			if strings.Contains(lowerName, keyword) {
				return true
			}
		}
	}

	return false
}

// checkRolesMapping checks if the config contains the critical Roles property mapping
func checkRolesMapping(config *authentik.AuthentikConfig) bool {
	for _, mapping := range config.PropertyMappings {
		// Check if this is a SAML mapping with the critical "Roles" attribute name
		if mapping.SAMLName == "Roles" {
			return true
		}
	}
	return false
}

// Subcommands

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

func listAuthentikBackups(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	backupDir, _ := cmd.Flags().GetString("dir")

	// Check if backup directory exists
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		logger.Warn("Backup directory does not exist",
			zap.String("directory", backupDir))
		logger.Info("To create first backup, run: eos backup authentik")
		return nil
	}

	// Find all backup files
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return fmt.Errorf("failed to read backup directory: %w", err)
	}

	backups := []backupFileInfo{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "authentik-backup-") {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		fullPath := filepath.Join(backupDir, entry.Name())
		info, err := parseBackupFile(fullPath)
		if err != nil {
			logger.Warn("Failed to parse backup file",
				zap.String("file", entry.Name()),
				zap.Error(err))
			continue
		}
		backups = append(backups, info)
	}

	if len(backups) == 0 {
		logger.Info("No Authentik backups found",
			zap.String("directory", backupDir))
		logger.Info("To create first backup, run: eos backup authentik")
		return nil
	}

	// Sort by modification time (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].ModTime.After(backups[j].ModTime)
	})

	// Display list
	logger.Info("Authentik Backups Found",
		zap.Int("total_backups", len(backups)),
		zap.String("directory", backupDir))

	for i, backup := range backups {
		sizeKB := backup.Size / 1024
		totalResources := backup.Providers + backup.Applications + backup.PropertyMappings +
			backup.Flows + backup.Stages + backup.Groups + backup.Policies +
			backup.Certificates + backup.Blueprints + backup.Outposts + backup.Tenants

		logger.Info(fmt.Sprintf("Backup %d", i+1),
			zap.String("file", filepath.Base(backup.Path)),
			zap.String("created", backup.ModTime.Format("2006-01-02 15:04")),
			zap.Int64("size_kb", sizeKB),
			zap.String("source", backup.SourceURL),
			zap.Int("resources", totalResources))
	}

	logger.Info("View details with: eos backup authentik show --latest")
	return nil
}

func showAuthentikBackup(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	backupDir, _ := cmd.Flags().GetString("dir")
	latest, _ := cmd.Flags().GetBool("latest")

	var targetFile string

	if len(args) > 0 {
		targetFile = args[0]
	} else if latest {
		// Find latest backup
		entries, err := os.ReadDir(backupDir)
		if err != nil {
			return fmt.Errorf("failed to read backup directory: %w", err)
		}

		var latestTime time.Time
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), "authentik-backup-") {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			if info.ModTime().After(latestTime) {
				latestTime = info.ModTime()
				targetFile = filepath.Join(backupDir, entry.Name())
			}
		}

		if targetFile == "" {
			logger.Info("No backups found", zap.String("directory", backupDir))
			return nil
		}
	} else {
		return fmt.Errorf("please specify a backup file or use --latest flag")
	}

	// Parse and display backup
	backup, err := parseBackupFile(targetFile)
	if err != nil {
		return fmt.Errorf("failed to parse backup: %w", err)
	}

	totalResources := backup.Providers + backup.Applications + backup.PropertyMappings +
		backup.Flows + backup.Stages + backup.Groups + backup.Policies +
		backup.Certificates + backup.Blueprints + backup.Outposts + backup.Tenants

	logger.Info("Authentik Backup Details",
		zap.String("file", backup.Path),
		zap.String("created", backup.ModTime.Format("2006-01-02 15:04:05")),
		zap.Int64("size_bytes", backup.Size),
		zap.String("source_url", backup.SourceURL),
		zap.String("version", backup.AuthentikVersion))

	logger.Info("Resource Counts",
		zap.Int("providers", backup.Providers),
		zap.Int("applications", backup.Applications),
		zap.Int("property_mappings", backup.PropertyMappings),
		zap.Int("flows", backup.Flows),
		zap.Int("stages", backup.Stages),
		zap.Int("groups", backup.Groups),
		zap.Int("policies", backup.Policies),
		zap.Int("certificates", backup.Certificates),
		zap.Int("blueprints", backup.Blueprints),
		zap.Int("outposts", backup.Outposts),
		zap.Int("tenants", backup.Tenants),
		zap.Int("total", totalResources))

	logger.Info("Restore this backup with: eos backup authentik restore " + backup.Path + " (coming soon)")
	return nil
}

type backupFileInfo struct {
	Path             string
	Size             int64
	ModTime          time.Time
	SourceURL        string
	AuthentikVersion string
	Providers        int
	Applications     int
	PropertyMappings int
	Flows            int
	Stages           int
	Groups           int
	Policies         int
	Certificates     int
	Blueprints       int
	Outposts         int
	Tenants          int
}

func parseBackupFile(path string) (backupFileInfo, error) {
	info := backupFileInfo{Path: path}

	// Get file stats
	stat, err := os.Stat(path)
	if err != nil {
		return info, err
	}
	info.Size = stat.Size()
	info.ModTime = stat.ModTime()

	// Read and parse backup file
	data, err := os.ReadFile(path)
	if err != nil {
		return info, err
	}

	// Parse as YAML
	var backup struct {
		Metadata struct {
			SourceURL        string `yaml:"source_url"`
			AuthentikVersion string `yaml:"authentik_version"`
		} `yaml:"metadata"`
		Providers        []interface{} `yaml:"providers"`
		Applications     []interface{} `yaml:"applications"`
		PropertyMappings []interface{} `yaml:"property_mappings"`
		Flows            []interface{} `yaml:"flows"`
		Stages           []interface{} `yaml:"stages"`
		Groups           []interface{} `yaml:"groups"`
		Policies         []interface{} `yaml:"policies"`
		Certificates     []interface{} `yaml:"certificates"`
		Blueprints       []interface{} `yaml:"blueprints"`
		Outposts         []interface{} `yaml:"outposts"`
		Tenants          []interface{} `yaml:"tenants"`
	}

	if err := yaml.Unmarshal(data, &backup); err != nil {
		return info, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Extract info
	info.SourceURL = backup.Metadata.SourceURL
	info.AuthentikVersion = backup.Metadata.AuthentikVersion
	info.Providers = len(backup.Providers)
	info.Applications = len(backup.Applications)
	info.PropertyMappings = len(backup.PropertyMappings)
	info.Flows = len(backup.Flows)
	info.Stages = len(backup.Stages)
	info.Groups = len(backup.Groups)
	info.Policies = len(backup.Policies)
	info.Certificates = len(backup.Certificates)
	info.Blueprints = len(backup.Blueprints)
	info.Outposts = len(backup.Outposts)
	info.Tenants = len(backup.Tenants)

	return info, nil
}

func restoreAuthentikBackup(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Determine backup file to restore
	var backupFile string
	if latest, _ := cmd.Flags().GetBool("latest"); latest {
		backupDir, _ := cmd.Flags().GetString("dir")
		entries, err := os.ReadDir(backupDir)
		if err != nil {
			return fmt.Errorf("failed to read backup directory: %w", err)
		}

		var latestTime time.Time
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), "authentik-backup-") {
				continue
			}
			if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.ModTime().After(latestTime) {
				latestTime = info.ModTime()
				backupFile = filepath.Join(backupDir, entry.Name())
			}
		}

		if backupFile == "" {
			return eos_err.NewUserError("no backups found in %s", backupDir)
		}
		logger.Info("Selected latest backup", zap.String("file", backupFile))
	} else {
		if len(args) == 0 {
			return eos_err.NewUserError("backup file required (or use --latest flag)")
		}
		backupFile = args[0]
	}

	// Check required flags
	url, _ := cmd.Flags().GetString("url")
	token, _ := cmd.Flags().GetString("token")
	if url == "" || token == "" {
		return eos_err.NewUserError("--url and --token are required for restore")
	}

	// Auto-add https:// if missing
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
		logger.Info("Added https:// prefix to URL", zap.String("url", url))
	}

	// Load backup file
	logger.Info("Loading backup file", zap.String("file", backupFile))
	backupData, err := os.ReadFile(backupFile)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	var backup authentik.AuthentikConfig
	if strings.HasSuffix(backupFile, ".json") {
		err = json.Unmarshal(backupData, &backup)
	} else {
		err = yaml.Unmarshal(backupData, &backup)
	}
	if err != nil {
		return fmt.Errorf("failed to parse backup file: %w", err)
	}

	logger.Info("Backup loaded successfully",
		zap.String("source", backup.Metadata.SourceURL),
		zap.String("version", backup.Metadata.AuthentikVersion),
		zap.Time("exported", backup.Metadata.ExportedAt),
		zap.Int("providers", len(backup.Providers)),
		zap.Int("applications", len(backup.Applications)))

	// Get restore options
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	skipExisting, _ := cmd.Flags().GetBool("skip-existing")
	updateExisting, _ := cmd.Flags().GetBool("update-existing")
	onlyTypes, _ := cmd.Flags().GetStringSlice("only-types")
	skipTypes, _ := cmd.Flags().GetStringSlice("skip-types")
	createBackup, _ := cmd.Flags().GetBool("create-backup")

	if dryRun {
		logger.Info("DRY RUN MODE - No changes will be made")
	}

	// INTERVENE - Create pre-restore backup if requested
	if createBackup && !dryRun {
		logger.Info("Creating pre-restore backup")
		// Create backup using same mechanism as backup command
		preBackupFile := fmt.Sprintf("/mnt/eos-backups/authentik/pre-restore-%s.yaml",
			time.Now().Format("20060102-150405"))

		types := []string{"providers", "applications", "mappings", "flows",
			"stages", "groups", "policies", "certificates", "blueprints", "outposts", "tenants"}

		preBackupConfig, err := authentik.ExtractConfigurationAPI(rc.Ctx, url, token, types, nil, nil, false)
		if err != nil {
			logger.Warn("Failed to create pre-restore backup", zap.Error(err))
		} else {
			preBackupData, _ := yaml.Marshal(preBackupConfig)
			if err := os.WriteFile(preBackupFile, preBackupData, shared.SecretFilePerm); err != nil {
				logger.Warn("Failed to save pre-restore backup", zap.Error(err))
			} else {
				logger.Info("Pre-restore backup created", zap.String("file", preBackupFile))
			}
		}
	}

	// EVALUATE - For now, log what would be restored and provide next steps
	logger.Info("Restore functionality is being implemented",
		zap.String("status", "coming_soon"),
		zap.String("backup_file", backupFile),
		zap.String("target_url", url),
		zap.Bool("dry_run", dryRun),
		zap.Bool("skip_existing", skipExisting),
		zap.Bool("update_existing", updateExisting),
		zap.Strings("only_types", onlyTypes),
		zap.Strings("skip_types", skipTypes))

	logger.Info("Restore command is available but implementation is in progress")
	logger.Info("To complete restore implementation, the existing pkg/authentik/import.go logic needs to be refactored to use structured logging and the consolidated client")

	return eos_err.NewUserError("restore functionality is coming soon - implementation in progress")
}
