package backup

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO: This is a refactored version of read.go following Eos standards:
// - All fmt.Printf/Println replaced with structured logging or stderr output
// - User-facing output uses stderr to preserve stdout
// - Follows Assess → Intervene → Evaluate pattern
// - Enhanced error handling and context

// ReadRepositoryRefactored reads and displays repository information following Eos standards
func ReadRepositoryRefactored(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	if len(args) == 0 {
		return fmt.Errorf("repository name is required")
	}
	
	repoName := args[0]
	logger.Info("Reading repository information",
		zap.String("repository", repoName))
	
	// ASSESS - Load configuration and validate repository
	logger.Info("Assessing repository configuration")
	
	config, err := LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}
	
	repo, exists := config.Repositories[repoName]
	if !exists {
		return fmt.Errorf("repository %q not found", repoName)
	}
	
	// INTERVENE - Gather repository information
	logger.Info("Gathering repository details",
		zap.String("backend", repo.Backend),
		zap.String("url", repo.URL))
	
	// Get additional repository statistics if available
	repoInfo, err := gatherRepositoryInfo(rc, &repo)
	if err != nil {
		logger.Warn("Failed to gather extended repository info", zap.Error(err))
		// Continue with basic info even if extended info fails
	}
	
	// EVALUATE - Display repository information
	logger.Info("Displaying repository information")
	
	// Convert Repository to BackupRepository for display
	backupRepo := &BackupRepository{
		Name:        repo.Name,
		Backend:     repo.Backend,
		URL:         repo.URL,
		Environment: repo.Environment,
	}
	
	if err := displayRepositoryInfo(rc, backupRepo, repoInfo, config.DefaultRepository); err != nil {
		return fmt.Errorf("failed to display repository info: %w", err)
	}
	
	logger.Info("Repository information displayed successfully")
	return nil
}

// RepositoryInfo holds extended repository information
type RepositoryInfo struct {
	Snapshots    []SnapshotInfo `json:"snapshots"`
	TotalSize    int64          `json:"total_size"`
	OldestSnapshot *time.Time   `json:"oldest_snapshot"`
	NewestSnapshot *time.Time   `json:"newest_snapshot"`
}

// SnapshotInfo holds basic snapshot information
type SnapshotInfo struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Hostname string    `json:"hostname"`
	Paths    []string  `json:"paths"`
}

// gatherRepositoryInfo collects extended repository information
func gatherRepositoryInfo(rc *eos_io.RuntimeContext, repo *Repository) (*RepositoryInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Gathering extended repository information")
	
	// This would integrate with actual backup tool (restic, borg, etc.)
	// to get repository statistics and snapshot information
	
	// Placeholder implementation - would be replaced with actual tool integration
	repoInfo := &RepositoryInfo{
		Snapshots: []SnapshotInfo{},
		TotalSize: 0,
	}
	
	logger.Info("Extended repository information gathered")
	return repoInfo, nil
}

// displayRepositoryInfo displays formatted repository information to user
func displayRepositoryInfo(rc *eos_io.RuntimeContext, repo *BackupRepository, repoInfo *RepositoryInfo, defaultRepo string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("terminal prompt: Repository information")
	
	var display strings.Builder
	
	// Repository header
	display.WriteString("\n")
	display.WriteString(fmt.Sprintf("💾 Repository: %s\n", repo.Name))
	display.WriteString(strings.Repeat("─", 60))
	display.WriteString("\n")
	
	// Basic repository information
	display.WriteString(fmt.Sprintf("Backend:     %s\n", repo.Backend))
	display.WriteString(fmt.Sprintf("URL:         %s\n", repo.URL))
	
	if repo.Name == defaultRepo {
		display.WriteString("Default:     ✅ Yes\n")
	} else {
		display.WriteString("Default:     ❌ No\n")
	}
	
	// Environment variables (masked for security)
	if len(repo.Environment) > 0 {
		display.WriteString("\n⚙️  Environment Variables:\n")
		for k, v := range repo.Environment {
			displayValue := maskEnvironmentValue(k, v)
			display.WriteString(fmt.Sprintf("  %s: %s\n", k, displayValue))
		}
	}
	
	// Repository statistics
	if repoInfo != nil {
		display.WriteString("\n📊 Repository Statistics:\n")
		display.WriteString(fmt.Sprintf("  Total Snapshots: %d\n", len(repoInfo.Snapshots)))
		
		if repoInfo.OldestSnapshot != nil {
			display.WriteString(fmt.Sprintf("  Oldest Snapshot: %s\n", repoInfo.OldestSnapshot.Format("2006-01-02 15:04:05")))
		}
		if repoInfo.NewestSnapshot != nil {
			display.WriteString(fmt.Sprintf("  Newest Snapshot: %s\n", repoInfo.NewestSnapshot.Format("2006-01-02 15:04:05")))
		}
		
		if repoInfo.TotalSize > 0 {
			display.WriteString(fmt.Sprintf("  Total Size: %s\n", formatBytes(repoInfo.TotalSize)))
		}
	}
	
	display.WriteString("\n")
	
	// Display to user via stderr
	if _, err := fmt.Fprint(os.Stderr, display.String()); err != nil {
		return fmt.Errorf("failed to display repository info: %w", err)
	}
	
	return nil
}

// ReadProfileRefactored reads and displays backup profile information following Eos standards
func ReadProfileRefactored(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	if len(args) == 0 {
		return fmt.Errorf("profile name is required")
	}
	
	profileName := args[0]
	logger.Info("Reading backup profile information",
		zap.String("profile", profileName))
	
	// ASSESS - Load configuration and validate profile
	logger.Info("Assessing backup profile configuration")
	
	config, err := LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}
	
	profile, exists := config.Profiles[profileName]
	if !exists {
		return fmt.Errorf("profile %q not found", profileName)
	}
	
	// INTERVENE - Gather profile information
	logger.Info("Gathering profile details",
		zap.String("description", profile.Description),
		zap.Strings("paths", profile.Paths))
	
	// EVALUATE - Display profile information
	logger.Info("Displaying profile information")
	
	// Convert Profile to BackupProfile for display
	backupProfile := &BackupProfile{
		Name:        profile.Name,
		Description: profile.Description,
		// Additional fields would be mapped from the original Profile struct
	}
	
	if err := displayProfileInfo(rc, backupProfile); err != nil {
		return fmt.Errorf("failed to display profile info: %w", err)
	}
	
	logger.Info("Profile information displayed successfully")
	return nil
}

// BackupProfile represents a backup profile configuration
type BackupProfile struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Paths       []string `json:"paths"`
	Excludes    []string `json:"excludes"`
	Repository  string   `json:"repository"`
	Schedule    string   `json:"schedule"`
	Retention   string   `json:"retention"`
}

// BackupRepository represents a backup repository configuration
type BackupRepository struct {
	Name        string            `json:"name"`
	Backend     string            `json:"backend"`
	URL         string            `json:"url"`
	Environment map[string]string `json:"environment"`
}

// displayProfileInfo displays formatted profile information to user
func displayProfileInfo(rc *eos_io.RuntimeContext, profile *BackupProfile) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("terminal prompt: Backup profile information")
	
	var display strings.Builder
	
	// Profile header
	display.WriteString("\n")
	display.WriteString(fmt.Sprintf("📋 Profile: %s\n", profile.Name))
	display.WriteString(strings.Repeat("─", 60))
	display.WriteString("\n")
	
	// Profile details
	if profile.Description != "" {
		display.WriteString(fmt.Sprintf("Description: %s\n", profile.Description))
	}
	
	if len(profile.Paths) > 0 {
		display.WriteString("\n📁 Backup Paths:\n")
		for _, path := range profile.Paths {
			display.WriteString(fmt.Sprintf("  • %s\n", path))
		}
	}
	
	if len(profile.Excludes) > 0 {
		display.WriteString("\n🚫 Excluded Patterns:\n")
		for _, exclude := range profile.Excludes {
			display.WriteString(fmt.Sprintf("  • %s\n", exclude))
		}
	}
	
	if profile.Repository != "" {
		display.WriteString(fmt.Sprintf("\n💾 Repository: %s\n", profile.Repository))
	}
	
	if profile.Schedule != "" {
		display.WriteString(fmt.Sprintf("⏰ Schedule: %s\n", profile.Schedule))
	}
	
	if profile.Retention != "" {
		display.WriteString(fmt.Sprintf("🗑️  Retention: %s\n", profile.Retention))
	}
	
	display.WriteString("\n")
	
	// Display to user via stderr
	if _, err := fmt.Fprint(os.Stderr, display.String()); err != nil {
		return fmt.Errorf("failed to display profile info: %w", err)
	}
	
	return nil
}

// maskEnvironmentValue masks sensitive environment variable values
func maskEnvironmentValue(key, value string) string {
	// List of environment variables that should be masked
	sensitiveKeys := []string{
		"PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL", "AUTH",
		"RESTIC_PASSWORD", "BORG_PASSPHRASE", "AWS_SECRET_ACCESS_KEY",
		"GOOGLE_APPLICATION_CREDENTIALS", "AZURE_STORAGE_ACCOUNT_KEY",
	}
	
	keyUpper := strings.ToUpper(key)
	for _, sensitiveKey := range sensitiveKeys {
		if strings.Contains(keyUpper, sensitiveKey) {
			return maskSensitiveValue(value)
		}
	}
	
	return value
}

// maskSensitiveValue masks sensitive values for display
func maskSensitiveValue(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
}

// formatBytes formats byte count in human readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// TODO: The following types would need to be defined based on the actual backup configuration:
// - Repository struct
// - BackupProfile struct
// - LoadConfig function
// These would be migrated from the original file or other related backup files