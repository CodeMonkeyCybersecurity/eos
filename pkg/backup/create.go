// pkg/backup/create.go

package backup

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var secretsDirPath = SecretsDir

func CreateRepository(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
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
	config, err := LoadConfig(rc)
	if err != nil {
		logger.Warn("Failed to load existing config, creating new",
			zap.Error(err))
		config = &Config{
			Repositories: make(map[string]Repository),
			Profiles:     make(map[string]Profile),
		}
	}

	// Check if repository already exists
	if _, exists := config.Repositories[name]; exists {
		return fmt.Errorf("repository %q already exists", name)
	}

	// Create repository configuration
	repo := Repository{
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
	vaultPath := fmt.Sprintf("%s/%s", VaultPasswordPathPrefix, name)
	logger.Info("Storing repository password in Vault",
		zap.String("path", vaultPath))

	vaultAddr := shared.GetVaultAddrWithEnv()

	// Try to connect to Vault
	_, err = vault.NewClient(vaultAddr, logger.Logger().Logger)
	if err != nil {
		// Fall back to local storage
		logger.Warn("Vault unavailable, storing password locally",
			zap.Error(err))

		if err := storeLocalPassword(name, password); err != nil {
			return fmt.Errorf("storing password locally: %w", err)
		}
	} else {
		secretData := map[string]interface{}{
			VaultPasswordKey: password,
			"backend":        backend,
			"url":            url,
		}

		err = vault.WriteToVault(rc, vaultPath, secretData)
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
	if err := SaveConfig(rc, config); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	logger.Info("Repository created successfully",
		zap.String("name", name),
		zap.String("backend", backend))

	// Initialize repository if requested
	if doInit {
		logger.Info("Initializing repository")

		client, err := NewClient(rc, name)
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

func CreateProfile(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
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
	config, err := LoadConfig(rc)
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
	profile := Profile{
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
		profile.Retention = &Retention{
			KeepLast:    retentionLast,
			KeepDaily:   retentionDaily,
			KeepWeekly:  retentionWeekly,
			KeepMonthly: retentionMonthly,
			KeepYearly:  retentionYearly,
		}
	}

	// Add schedule if specified
	if schedule != "" {
		profile.Schedule = &Schedule{
			Cron: schedule,
		}
	}

	// Add profile to config
	config.Profiles[name] = profile

	// Save configuration
	if err := SaveConfig(rc, config); err != nil {
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

// generateSecurePassword generates a cryptographically secure random password
// SECURITY: Uses crypto/rand to ensure unpredictable passwords for backup encryption
func generateSecurePassword() (string, error) {
	const (
		length  = 32
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
	)

	// Generate random bytes
	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random password: %w", err)
	}

	// Map random bytes to charset to ensure printable characters
	password := make([]byte, length)
	for i, b := range randomBytes {
		password[i] = charset[int(b)%len(charset)]
	}

	return string(password), nil
}

func storeLocalPassword(repoName, password string) error {
	repoName = strings.TrimSpace(repoName)
	if repoName == "" {
		return fmt.Errorf("repository name is required")
	}
	if strings.Contains(repoName, "/") || strings.Contains(repoName, "..") {
		return fmt.Errorf("invalid repository name %q", repoName)
	}

	if err := os.MkdirAll(secretsDirPath, PasswordDirPerm); err != nil {
		return fmt.Errorf("creating secrets directory: %w", err)
	}

	passwordPath := filepath.Join(secretsDirPath, fmt.Sprintf("%s.password", repoName))
	if err := os.WriteFile(passwordPath, []byte(password), PasswordFilePerm); err != nil {
		return fmt.Errorf("writing password file: %w", err)
	}

	if err := os.Chmod(passwordPath, PasswordFilePerm); err != nil {
		return fmt.Errorf("setting password file permissions: %w", err)
	}

	return nil
}
