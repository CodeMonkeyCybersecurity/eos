// pkg/hecate/env_manager.go
// Unified .env file management for Hecate services
// RATIONALE: Generic, reusable system for reading/writing/validating .env files
// ARCHITECTURE: Can be used for ANY service (not just email configuration)

package hecate

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// EnvVariable represents a single environment variable with validation rules
type EnvVariable struct {
	Key          string             // Variable name (e.g., "AUTHENTIK_EMAIL__HOST")
	Value        string             // Current value (populated by LoadEnv)
	Required     bool               // Must be non-empty
	IsSecret     bool               // Hide input during prompting (for passwords)
	Validator    func(string) error // Custom validation function
	HelpText     string             // WHY needed, HOW to get value
	DefaultValue string             // Default if not provided
	AllowEmpty   bool               // Allow empty value if not Required
}

// EnvManager handles .env file operations with atomic writes and backups
type EnvManager struct {
	FilePath   string                  // Absolute path to .env file
	Variables  map[string]*EnvVariable // All variables (key = variable name)
	BackupPath string                  // Path to backup file (set after backup)
}

// NewEnvManager creates a new .env file manager
// ASSESS: Validates file path exists and is readable
func NewEnvManager(filePath string) (*EnvManager, error) {
	if filePath == "" {
		return nil, fmt.Errorf("env file path is required")
	}

	// Verify file exists
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(".env file not found: %s", filePath)
		}
		return nil, fmt.Errorf("failed to access .env file %s: %w", filePath, err)
	}

	return &EnvManager{
		FilePath:  filePath,
		Variables: make(map[string]*EnvVariable),
	}, nil
}

// LoadEnv reads the .env file and populates variable values
// ASSESS: Parses .env file into key-value map
func (em *EnvManager) LoadEnv(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	file, err := os.Open(em.FilePath)
	if err != nil {
		return fmt.Errorf("failed to open .env file: %w", err)
	}
	defer file.Close()

	logger.Debug("Loading .env file",
		zap.String("path", em.FilePath))

	scanner := bufio.NewScanner(file)
	lineNum := 0
	loaded := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			logger.Warn("Skipping malformed line in .env file",
				zap.Int("line", lineNum),
				zap.String("content", line))
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// If variable is tracked, update its value
		if envVar, exists := em.Variables[key]; exists {
			envVar.Value = value
			loaded++
			logger.Debug("Loaded variable from .env",
				zap.String("key", key),
				zap.Bool("has_value", value != ""),
				zap.Bool("is_secret", envVar.IsSecret))
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read .env file: %w", err)
	}

	logger.Info("Loaded .env file",
		zap.String("path", em.FilePath),
		zap.Int("tracked_variables_loaded", loaded),
		zap.Int("total_tracked", len(em.Variables)))

	return nil
}

// CheckMissingVariables identifies required variables that are missing or empty
// ASSESS: Detects which variables need user input
func (em *EnvManager) CheckMissingVariables(requiredVars []*EnvVariable) ([]*EnvVariable, error) {
	var missing []*EnvVariable

	for _, reqVar := range requiredVars {
		// Add to tracked variables if not already present
		if _, exists := em.Variables[reqVar.Key]; !exists {
			em.Variables[reqVar.Key] = reqVar
		}

		// Check if variable is missing or empty
		existingVar := em.Variables[reqVar.Key]
		if existingVar.Required && strings.TrimSpace(existingVar.Value) == "" {
			missing = append(missing, existingVar)
		}
	}

	return missing, nil
}

// PromptForVariables interactively collects values for missing variables
// INTERVENE: Prompts user with validation and retry logic
func (em *EnvManager) PromptForVariables(rc *eos_io.RuntimeContext, missing []*EnvVariable) error {
	logger := otelzap.Ctx(rc.Ctx)

	if len(missing) == 0 {
		logger.Info("No missing variables - all required values present")
		return nil
	}

	logger.Info("Collecting missing environment variables",
		zap.Int("count", len(missing)))

	for _, envVar := range missing {
		// Build prompt configuration
		promptConfig := &interaction.RequiredFlagConfig{
			FlagName:      envVar.Key,
			PromptMessage: fmt.Sprintf("Enter %s: ", envVar.Key),
			HelpText:      envVar.HelpText,
			IsSecret:      envVar.IsSecret,
			AllowEmpty:    envVar.AllowEmpty,
		}

		// Prompt user for value (with validation and retry)
		result, err := interaction.GetRequiredString(
			rc,
			"",    // No flag value (prompting mode)
			false, // Flag not set via CLI
			promptConfig,
		)
		if err != nil {
			return fmt.Errorf("failed to collect %s: %w", envVar.Key, err)
		}

		value := result.Value

		// Apply default if empty and default exists
		if value == "" && envVar.DefaultValue != "" {
			value = envVar.DefaultValue
			logger.Info("Using default value",
				zap.String("key", envVar.Key),
				zap.String("default", envVar.DefaultValue))
		}

		// Validate if custom validator provided
		if envVar.Validator != nil {
			if err := envVar.Validator(value); err != nil {
				return fmt.Errorf("validation failed for %s: %w", envVar.Key, err)
			}
		}

		// Update variable value
		envVar.Value = value
		logger.Info("Variable value collected",
			zap.String("key", envVar.Key),
			zap.String("source", string(result.Source)),
			zap.Bool("is_secret", envVar.IsSecret))
	}

	return nil
}

// WriteEnv writes all variables to .env file with atomic write and backup
// INTERVENE: Creates backup, writes atomically, sets correct permissions
func (em *EnvManager) WriteEnv(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create backup before modifying
	if err := em.CreateBackup(rc); err != nil {
		return fmt.Errorf("failed to create backup before write: %w", err)
	}

	// Read entire existing .env file
	existingContent, err := os.ReadFile(em.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read existing .env file: %w", err)
	}

	// Parse existing content line by line
	lines := strings.Split(string(existingContent), "\n")
	updatedLines := make([]string, 0, len(lines))
	updatedKeys := make(map[string]bool)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Preserve comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			updatedLines = append(updatedLines, line)
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			// Preserve malformed lines (warn user during load)
			updatedLines = append(updatedLines, line)
			continue
		}

		key := strings.TrimSpace(parts[0])

		// If we're tracking this variable, use our value
		if envVar, exists := em.Variables[key]; exists {
			updatedLines = append(updatedLines, fmt.Sprintf("%s=%s", key, envVar.Value))
			updatedKeys[key] = true
			logger.Debug("Updated variable in .env",
				zap.String("key", key),
				zap.Bool("is_secret", envVar.IsSecret))
		} else {
			// Preserve untracked variables unchanged
			updatedLines = append(updatedLines, line)
		}
	}

	// Append any new variables that weren't in the original file
	for key, envVar := range em.Variables {
		if !updatedKeys[key] && envVar.Value != "" {
			updatedLines = append(updatedLines, fmt.Sprintf("%s=%s", key, envVar.Value))
			logger.Debug("Added new variable to .env",
				zap.String("key", key),
				zap.Bool("is_secret", envVar.IsSecret))
		}
	}

	// Write to temporary file first (atomic write pattern)
	tempFile := em.FilePath + ".tmp"
	content := strings.Join(updatedLines, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	if err := os.WriteFile(tempFile, []byte(content), TempFilePerm); err != nil {
		return fmt.Errorf("failed to write temp .env file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempFile, em.FilePath); err != nil {
		os.Remove(tempFile) // Cleanup temp file
		return fmt.Errorf("failed to replace .env file: %w", err)
	}

	// Set correct permissions (0600 - root read/write only, contains secrets)
	if err := os.Chmod(em.FilePath, EnvFilePerm); err != nil {
		return fmt.Errorf("failed to set .env permissions: %w", err)
	}

	logger.Info("Updated .env file",
		zap.String("path", em.FilePath),
		zap.Int("variables_updated", len(updatedKeys)),
		zap.String("backup", em.BackupPath))

	return nil
}

// CreateBackup creates a timestamped backup of the .env file
// SECURITY: Ensures we can rollback if something goes wrong
func (em *EnvManager) CreateBackup(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	timestamp := time.Now().Format("20060102-150405")
	backupDir := filepath.Dir(em.FilePath)
	backupName := fmt.Sprintf(".env.backup-%s", timestamp)
	em.BackupPath = filepath.Join(backupDir, backupName)

	// Read current .env content
	content, err := os.ReadFile(em.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read .env for backup: %w", err)
	}

	// Write backup with same permissions as original
	if err := os.WriteFile(em.BackupPath, content, EnvFilePerm); err != nil {
		return fmt.Errorf("failed to write .env backup: %w", err)
	}

	logger.Info("Created .env backup",
		zap.String("backup_path", em.BackupPath),
		zap.Int("size_bytes", len(content)))

	return nil
}

// RestoreBackup restores the .env file from backup
// SECURITY: Rollback mechanism if write fails
func (em *EnvManager) RestoreBackup(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	if em.BackupPath == "" {
		return fmt.Errorf("no backup available to restore")
	}

	content, err := os.ReadFile(em.BackupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	if err := os.WriteFile(em.FilePath, content, EnvFilePerm); err != nil {
		return fmt.Errorf("failed to restore .env from backup: %w", err)
	}

	logger.Info("Restored .env from backup",
		zap.String("backup_path", em.BackupPath),
		zap.String("restored_to", em.FilePath))

	return nil
}

// ============================================================================
// VALIDATION HELPERS
// ============================================================================
// NOTE: ValidatePort is provided by pkg/hecate/validation.go
// Additional email and timeout validators are defined here as they're specific
// to email configuration and not part of the general validation suite.

// ValidateEmailAddress validates email format
func ValidateEmailAddress(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email address is required")
	}

	// Basic email validation (has @ and .)
	if !strings.Contains(email, "@") {
		return fmt.Errorf("invalid email format (missing @)")
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid email format (multiple @)")
	}

	if !strings.Contains(parts[1], ".") {
		return fmt.Errorf("invalid email domain (missing .)")
	}

	return nil
}

// ValidateHostname validates hostname format
func ValidateHostname(hostname string) error {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return fmt.Errorf("hostname is required")
	}

	// Basic hostname validation
	if len(hostname) > MaxDNSLength {
		return fmt.Errorf("hostname too long (max %d characters)", MaxDNSLength)
	}

	// Reject obvious invalids
	if strings.Contains(hostname, " ") {
		return fmt.Errorf("hostname cannot contain spaces")
	}

	return nil
}

// ValidateBoolean validates true/false values
func ValidateBoolean(value string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fmt.Errorf("value is required")
	}

	if value != "true" && value != "false" {
		return fmt.Errorf("must be 'true' or 'false'")
	}

	return nil
}

// ValidateTimeout validates timeout value (positive integer)
func ValidateTimeout(timeout string) error {
	timeout = strings.TrimSpace(timeout)
	if timeout == "" {
		return fmt.Errorf("timeout is required")
	}

	timeoutNum, err := strconv.Atoi(timeout)
	if err != nil {
		return fmt.Errorf("timeout must be a number")
	}

	if timeoutNum < 1 {
		return fmt.Errorf("timeout must be positive")
	}

	if timeoutNum > 300 {
		return fmt.Errorf("timeout too long (max 300 seconds)")
	}

	return nil
}
