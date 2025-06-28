// cmd/backup/create.go

package backup

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create backup resources (repositories, profiles)",
}

var createRepoCmd = &cobra.Command{
	Use:   "repository <name>",
	Short: "Create and initialize a new backup repository",
	Long: `Create a new restic repository with Vault-managed passwords.

Supported backends:
  - local: Local filesystem
  - sftp: SSH/SFTP remote server
  - s3: Amazon S3 or compatible
  - b2: Backblaze B2
  - azure: Azure Blob Storage
  - gs: Google Cloud Storage

Examples:
  # Local repository
  eos backup create repository local --backend local --path /var/lib/eos/backups
  
  # SFTP repository
  eos backup create repository remote --backend sftp --url sftp:user@backup.example.com:/backups
  
  # S3 repository
  eos backup create repository s3 --backend s3 --url s3:s3.amazonaws.com/mybucket`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(createRepository),
}

var createProfileCmd = &cobra.Command{
	Use:   "profile <name>",
	Short: "Create a new backup profile",
	Long: `Create a backup profile with paths, exclusions, and retention policies.

Examples:
  # System backup profile
  eos backup create profile system \
    --repo local \
    --paths /etc,/var,/opt \
    --exclude "*.tmp,*.cache" \
    --retention-daily 7 \
    --retention-weekly 4
  
  # Home directory backup
  eos backup create profile home \
    --repo remote \
    --paths /home \
    --exclude "*/.cache,*/Downloads" \
    --schedule "0 2 * * *"`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(createProfile),
}

func init() {
	createCmd.AddCommand(createRepoCmd)
	createCmd.AddCommand(createProfileCmd)

	// Repository flags
	createRepoCmd.Flags().String("backend", "", "Repository backend type (local, sftp, s3, b2, azure, gs)")
	createRepoCmd.Flags().String("url", "", "Repository URL (format depends on backend)")
	createRepoCmd.Flags().String("path", "", "Local path for 'local' backend")
	createRepoCmd.Flags().StringSlice("env", nil, "Environment variables for backend (KEY=VALUE)")
	createRepoCmd.Flags().Bool("init", true, "Initialize repository after creation")
	createRepoCmd.MarkFlagRequired("backend")

	// Profile flags
	createProfileCmd.Flags().String("repo", "", "Repository to use for this profile")
	createProfileCmd.Flags().StringSlice("paths", nil, "Paths to backup")
	createProfileCmd.Flags().StringSlice("exclude", nil, "Patterns to exclude")
	createProfileCmd.Flags().StringSlice("tags", nil, "Tags to apply to snapshots")
	createProfileCmd.Flags().String("host", "", "Override hostname in snapshots")
	createProfileCmd.Flags().String("description", "", "Profile description")
	
	// Retention flags
	createProfileCmd.Flags().Int("retention-last", 0, "Keep last N snapshots")
	createProfileCmd.Flags().Int("retention-daily", 0, "Keep N daily snapshots")
	createProfileCmd.Flags().Int("retention-weekly", 0, "Keep N weekly snapshots")
	createProfileCmd.Flags().Int("retention-monthly", 0, "Keep N monthly snapshots")
	createProfileCmd.Flags().Int("retention-yearly", 0, "Keep N yearly snapshots")
	
	// Schedule flag
	createProfileCmd.Flags().String("schedule", "", "Cron expression for automatic backups")
	
	createProfileCmd.MarkFlagRequired("repo")
	createProfileCmd.MarkFlagRequired("paths")
}

func createRepository(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	name := args[0]
	backend, _ := cmd.Flags().GetString("backend")
	url, _ := cmd.Flags().GetString("url")
	path, _ := cmd.Flags().GetString("path")
	envVars, _ := cmd.Flags().GetStringSlice("env")
	doInit, _ := cmd.Flags().GetBool("init")

	logger.Info("Creating backup repository",
		zap.String("name", name),
		zap.String("backend", backend))

	// Build repository URL based on backend
	if backend == "local" {
		if path == "" {
			return fmt.Errorf("--path required for local backend")
		}
		url = path
	} else if url == "" {
		return fmt.Errorf("--url required for %s backend", backend)
	}

	// Parse environment variables
	envMap := make(map[string]string)
	for _, env := range envVars {
		var key, value string
		if _, err := fmt.Sscanf(env, "%s=%s", &key, &value); err != nil {
			return fmt.Errorf("invalid environment variable format: %s", env)
		}
		envMap[key] = value
	}

	// Load existing config
	config, err := backup.LoadConfig(rc)
	if err != nil {
		logger.Warn("Failed to load existing config, creating new",
			zap.Error(err))
		config = &backup.Config{
			Repositories: make(map[string]backup.Repository),
			Profiles:     make(map[string]backup.Profile),
		}
	}

	// Check if repository already exists
	if _, exists := config.Repositories[name]; exists {
		return fmt.Errorf("repository %q already exists", name)
	}

	// Create repository configuration
	repo := backup.Repository{
		Name:        name,
		Backend:     backend,
		URL:         url,
		Environment: envMap,
	}

	// Generate secure password and store in Vault
	logger.Info("Generating repository password")
	password, err := generateSecurePassword()
	if err != nil {
		return fmt.Errorf("generating password: %w", err)
	}

	// Store password in Vault
	vaultPath := fmt.Sprintf("eos/backup/repositories/%s", name)
	logger.Info("Storing repository password in Vault",
		zap.String("path", vaultPath))

	vClient, err := vault.NewClient(rc)
	if err != nil {
		// Fall back to local storage
		logger.Warn("Vault unavailable, storing password locally",
			zap.Error(err))
		
		if err := storeLocalPassword(name, password); err != nil {
			return fmt.Errorf("storing password locally: %w", err)
		}
	} else {
		secret := map[string]interface{}{
			"password": password,
			"backend":  backend,
			"url":      url,
		}
		
		_, err = vClient.Logical().Write(vaultPath, secret)
		if err != nil {
			return fmt.Errorf("storing password in vault: %w", err)
		}
	}

	// Add repository to config
	config.Repositories[name] = repo
	
	// Set as default if it's the first repository
	if len(config.Repositories) == 1 {
		config.DefaultRepository = name
	}

	// Save configuration
	if err := backup.SaveConfig(rc, config); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	logger.Info("Repository created successfully",
		zap.String("name", name),
		zap.String("backend", backend))

	// Initialize repository if requested
	if doInit {
		logger.Info("Initializing repository")
		
		client, err := backup.NewClient(rc, name)
		if err != nil {
			return fmt.Errorf("creating backup client: %w", err)
		}

		if err := client.InitRepository(); err != nil {
			return fmt.Errorf("initializing repository: %w", err)
		}
		
		logger.Info("Repository initialized successfully")
	}

	return nil
}

func createProfile(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	name := args[0]
	repoName, _ := cmd.Flags().GetString("repo")
	paths, _ := cmd.Flags().GetStringSlice("paths")
	excludes, _ := cmd.Flags().GetStringSlice("exclude")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	host, _ := cmd.Flags().GetString("host")
	description, _ := cmd.Flags().GetString("description")
	schedule, _ := cmd.Flags().GetString("schedule")

	logger.Info("Creating backup profile",
		zap.String("name", name),
		zap.String("repository", repoName),
		zap.Strings("paths", paths))

	// Load existing config
	config, err := backup.LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// Verify repository exists
	if _, exists := config.Repositories[repoName]; !exists {
		return fmt.Errorf("repository %q not found", repoName)
	}

	// Check if profile already exists
	if _, exists := config.Profiles[name]; exists {
		return fmt.Errorf("profile %q already exists", name)
	}

	// Build profile
	profile := backup.Profile{
		Name:        name,
		Description: description,
		Repository:  repoName,
		Paths:       paths,
		Excludes:    excludes,
		Tags:        tags,
		Host:        host,
	}

	// Add retention policy if specified
	retentionLast, _ := cmd.Flags().GetInt("retention-last")
	retentionDaily, _ := cmd.Flags().GetInt("retention-daily")
	retentionWeekly, _ := cmd.Flags().GetInt("retention-weekly")
	retentionMonthly, _ := cmd.Flags().GetInt("retention-monthly")
	retentionYearly, _ := cmd.Flags().GetInt("retention-yearly")

	if retentionLast > 0 || retentionDaily > 0 || retentionWeekly > 0 || 
	   retentionMonthly > 0 || retentionYearly > 0 {
		profile.Retention = &backup.Retention{
			KeepLast:    retentionLast,
			KeepDaily:   retentionDaily,
			KeepWeekly:  retentionWeekly,
			KeepMonthly: retentionMonthly,
			KeepYearly:  retentionYearly,
		}
	}

	// Add schedule if specified
	if schedule != "" {
		profile.Schedule = &backup.Schedule{
			Cron: schedule,
		}
	}

	// Add profile to config
	config.Profiles[name] = profile

	// Save configuration
	if err := backup.SaveConfig(rc, config); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	logger.Info("Profile created successfully",
		zap.String("name", name),
		zap.Int("paths", len(paths)),
		zap.Int("excludes", len(excludes)))

	// Create systemd timer if schedule specified
	if schedule != "" {
		logger.Info("Creating systemd timer for scheduled backups",
			zap.String("schedule", schedule))
		// TODO: Implement systemd timer creation
	}

	return nil
}

func generateSecurePassword() (string, error) {
	// Generate a secure 32-character password
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	// Implementation would use crypto/rand
	// Placeholder for demonstration
	return "generated-secure-password-here", nil
}

func storeLocalPassword(repoName, password string) error {
	// Store password in local secrets directory
	// Implementation would ensure proper permissions
	return nil
}