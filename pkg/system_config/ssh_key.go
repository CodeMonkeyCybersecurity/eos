// pkg/system_config/ssh_key.go
package system_config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SSHKeyManager handles SSH key generation and management
type SSHKeyManager struct {
	config *SSHKeyConfig
	rc     *eos_io.RuntimeContext
}

// NewSSHKeyManager creates a new SSHKeyManager instance
func NewSSHKeyManager(rc *eos_io.RuntimeContext, config *SSHKeyConfig) *SSHKeyManager {
	if config == nil {
		config = &SSHKeyConfig{
			KeyType:   "ed25519",
			FilePath:  filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519"),
			Overwrite: false,
		}
	}
	return &SSHKeyManager{
		config: config,
		rc:     rc,
	}
}

// GetType returns the configuration type
func (skm *SSHKeyManager) GetType() ConfigurationType {
	return ConfigTypeSSHKey
}

// Validate validates the SSH key configuration
func (skm *SSHKeyManager) Validate() error {
	// Validate email
	if err := ValidateEmail(skm.config.Email); err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	// Validate key type
	validKeyTypes := []string{"rsa", "dsa", "ecdsa", "ed25519"}
	if !contains(validKeyTypes, skm.config.KeyType) {
		return fmt.Errorf("invalid key type: %s, must be one of: %s",
			skm.config.KeyType, strings.Join(validKeyTypes, ", "))
	}

	// Validate key length for specific types
	switch skm.config.KeyType {
	case "rsa":
		if skm.config.KeyLength == 0 {
			skm.config.KeyLength = 4096 // Default
		}
		if skm.config.KeyLength < 2048 {
			return fmt.Errorf("RSA key length must be at least 2048 bits")
		}
	case "ecdsa":
		if skm.config.KeyLength == 0 {
			skm.config.KeyLength = 256 // Default
		}
		validECDSA := []int{256, 384, 521}
		valid := false
		for _, v := range validECDSA {
			if skm.config.KeyLength == v {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("ECDSA key length must be 256, 384, or 521")
		}
	case "dsa":
		return fmt.Errorf("DSA keys are deprecated and not recommended")
	case "ed25519":
		// ED25519 doesn't use key length
		skm.config.KeyLength = 0
	}

	// Validate file path
	if skm.config.FilePath == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	// Check if file already exists and overwrite is false
	if CheckFileExists(skm.config.FilePath) && !skm.config.Overwrite {
		return fmt.Errorf("SSH key already exists at %s (use --overwrite to replace)", skm.config.FilePath)
	}

	return nil
}

// Backup creates a backup of existing SSH keys
func (skm *SSHKeyManager) Backup() (*ConfigurationBackup, error) {
	logger := otelzap.Ctx(skm.rc.Ctx)

	backup := &ConfigurationBackup{
		ID:        fmt.Sprintf("ssh-key-%d", time.Now().Unix()),
		Type:      ConfigTypeSSHKey,
		Timestamp: time.Now(),
		Files:     make(map[string]string),
		Metadata:  make(map[string]interface{}),
	}

	logger.Info("Creating SSH key backup")

	// Backup existing private key
	if CheckFileExists(skm.config.FilePath) {
		content, err := os.ReadFile(skm.config.FilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read existing private key: %w", err)
		}
		backup.Files[skm.config.FilePath] = string(content)
	}

	// Backup existing public key
	pubKeyPath := skm.config.FilePath + ".pub"
	if CheckFileExists(pubKeyPath) {
		content, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read existing public key: %w", err)
		}
		backup.Files[pubKeyPath] = string(content)
	}

	// Store metadata
	backup.Metadata["key_type"] = skm.config.KeyType
	backup.Metadata["key_length"] = skm.config.KeyLength
	backup.Metadata["file_path"] = skm.config.FilePath

	return backup, nil
}

// Apply generates the SSH key
func (skm *SSHKeyManager) Apply() (*ConfigurationResult, error) {
	logger := otelzap.Ctx(skm.rc.Ctx)

	start := time.Now()
	result := &ConfigurationResult{
		Type:      ConfigTypeSSHKey,
		Timestamp: start,
		Steps:     make([]ConfigurationStep, 0),
		Changes:   make([]ConfigurationChange, 0),
		Warnings:  make([]string, 0),
	}

	logger.Info("Generating SSH key",
		zap.String("type", skm.config.KeyType),
		zap.String("path", skm.config.FilePath))

	// Step 1: Create .ssh directory
	if err := skm.createSSHDirectory(result); err != nil {
		result.Success = false
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}

	// Step 2: Generate SSH key
	if err := skm.generateSSHKey(result); err != nil {
		result.Success = false
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}

	// Step 3: Set proper permissions
	if err := skm.setPermissions(result); err != nil {
		result.Success = false
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}

	result.Success = true
	result.Message = fmt.Sprintf("SSH key generated successfully at %s", skm.config.FilePath)
	result.Duration = time.Since(start)

	logger.Info("SSH key generation completed",
		zap.String("type", skm.config.KeyType),
		zap.Duration("duration", result.Duration))

	return result, nil
}

// createSSHDirectory creates the .ssh directory if it doesn't exist
func (skm *SSHKeyManager) createSSHDirectory(result *ConfigurationResult) error {
	step := ConfigurationStep{
		Name:        "Create SSH Directory",
		Description: "Creating .ssh directory with proper permissions",
		Status:      "running",
	}
	stepStart := time.Now()

	sshDir := filepath.Dir(skm.config.FilePath)

	if err := EnsureDirectory(sshDir); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}

	// Set proper permissions for .ssh directory
	if err := os.Chmod(sshDir, 0700); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}

	step.Status = "completed"
	step.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, step)

	result.Changes = append(result.Changes, ConfigurationChange{
		Type:        "directory",
		Target:      sshDir,
		Action:      "created",
		Description: "Created .ssh directory with proper permissions",
	})

	return nil
}

// generateSSHKey generates the actual SSH key pair
func (skm *SSHKeyManager) generateSSHKey(result *ConfigurationResult) error {
	step := ConfigurationStep{
		Name:        "Generate SSH Key",
		Description: fmt.Sprintf("Generating %s SSH key pair", skm.config.KeyType),
		Status:      "running",
	}
	stepStart := time.Now()

	var args []string
	args = append(args, "-t", skm.config.KeyType)

	// Add key length for types that support it
	if skm.config.KeyType != "ed25519" && skm.config.KeyLength > 0 {
		args = append(args, "-b", fmt.Sprintf("%d", skm.config.KeyLength))
	}

	// Add comment (email)
	args = append(args, "-C", skm.config.Email)

	// Add file path
	args = append(args, "-f", skm.config.FilePath)

	// Add passphrase (empty string for no passphrase)
	passphrase := skm.config.Passphrase
	if passphrase == "" {
		passphrase = ""
	}
	args = append(args, "-N", passphrase)

	// Add additional comment if provided
	if skm.config.Comment != "" {
		args = append(args, "-C", skm.config.Comment)
	}

	if err := RunCommand(skm.rc, "generate ssh key", "ssh-keygen", args...); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}

	step.Status = "completed"
	step.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, step)

	result.Changes = append(result.Changes, ConfigurationChange{
		Type:        "file",
		Target:      skm.config.FilePath,
		Action:      "created",
		Description: fmt.Sprintf("Generated %s SSH key pair", skm.config.KeyType),
	})

	return nil
}

// setPermissions sets proper permissions on SSH key files
func (skm *SSHKeyManager) setPermissions(result *ConfigurationResult) error {
	step := ConfigurationStep{
		Name:        "Set Permissions",
		Description: "Setting proper permissions on SSH key files",
		Status:      "running",
	}
	stepStart := time.Now()

	// Set permissions on private key (600 - read/write for owner only)
	if err := os.Chmod(skm.config.FilePath, 0600); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}

	// Set permissions on public key (644 - read for all, write for owner)
	pubKeyPath := skm.config.FilePath + ".pub"
	if CheckFileExists(pubKeyPath) {
		if err := os.Chmod(pubKeyPath, 0644); err != nil {
			step.Status = "failed"
			step.Error = err.Error()
			step.Duration = time.Since(stepStart)
			result.Steps = append(result.Steps, step)
			return err
		}
	}

	step.Status = "completed"
	step.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, step)

	result.Changes = append(result.Changes, ConfigurationChange{
		Type:        "permissions",
		Target:      skm.config.FilePath,
		Action:      "modified",
		Description: "Set proper permissions on SSH key files",
	})

	return nil
}

// Rollback removes generated SSH keys
func (skm *SSHKeyManager) Rollback(backup *ConfigurationBackup) error {
	logger := otelzap.Ctx(skm.rc.Ctx)

	logger.Info("Rolling back SSH key generation", zap.String("backup_id", backup.ID))

	// Restore backed up files
	for filePath, content := range backup.Files {
		if err := WriteFile(filePath, content, 0600); err != nil {
			logger.Warn("Failed to restore file", zap.String("file", filePath), zap.Error(err))
		}
	}

	// If no backup existed, remove the generated files
	if len(backup.Files) == 0 {
		// Remove private key
		if CheckFileExists(skm.config.FilePath) {
			if err := os.Remove(skm.config.FilePath); err != nil {
				logger.Warn("Failed to remove private key", zap.String("file", skm.config.FilePath), zap.Error(err))
			}
		}

		// Remove public key
		pubKeyPath := skm.config.FilePath + ".pub"
		if CheckFileExists(pubKeyPath) {
			if err := os.Remove(pubKeyPath); err != nil {
				logger.Warn("Failed to remove public key", zap.String("file", pubKeyPath), zap.Error(err))
			}
		}
	}

	return nil
}

// Status returns the current status of SSH key configuration
func (skm *SSHKeyManager) Status() (*ConfigurationStatus, error) {
	status := &ConfigurationStatus{
		Type:       ConfigTypeSSHKey,
		Configured: CheckFileExists(skm.config.FilePath),
		Health: ConfigurationHealth{
			Status: "unknown",
			Checks: make([]HealthCheck, 0),
		},
		Files: make([]FileStatus, 0),
	}

	// Check private key
	if CheckFileExists(skm.config.FilePath) {
		fileInfo, err := os.Stat(skm.config.FilePath)
		if err == nil {
			status.Files = append(status.Files, FileStatus{
				Path:     skm.config.FilePath,
				Exists:   true,
				Mode:     fileInfo.Mode().String(),
				Size:     fileInfo.Size(),
				Modified: fileInfo.ModTime(),
			})

			// Check permissions
			if fileInfo.Mode().Perm() == 0600 {
				status.Health.Checks = append(status.Health.Checks, HealthCheck{
					Name:    "Private Key Permissions",
					Status:  "passed",
					Message: "Private key has correct permissions (600)",
				})
			} else {
				status.Health.Checks = append(status.Health.Checks, HealthCheck{
					Name:    "Private Key Permissions",
					Status:  "failed",
					Message: fmt.Sprintf("Private key has incorrect permissions (%s), should be 600", fileInfo.Mode().Perm().String()),
				})
			}
		}
	}

	// Check public key
	pubKeyPath := skm.config.FilePath + ".pub"
	if CheckFileExists(pubKeyPath) {
		fileInfo, err := os.Stat(pubKeyPath)
		if err == nil {
			status.Files = append(status.Files, FileStatus{
				Path:     pubKeyPath,
				Exists:   true,
				Mode:     fileInfo.Mode().String(),
				Size:     fileInfo.Size(),
				Modified: fileInfo.ModTime(),
			})

			// Check permissions
			if fileInfo.Mode().Perm() == 0644 {
				status.Health.Checks = append(status.Health.Checks, HealthCheck{
					Name:    "Public Key Permissions",
					Status:  "passed",
					Message: "Public key has correct permissions (644)",
				})
			} else {
				status.Health.Checks = append(status.Health.Checks, HealthCheck{
					Name:    "Public Key Permissions",
					Status:  "failed",
					Message: fmt.Sprintf("Public key has incorrect permissions (%s), should be 644", fileInfo.Mode().Perm().String()),
				})
			}
		}
	}

	// Determine overall health
	if status.Configured {
		status.Health.Status = "healthy"
		for _, check := range status.Health.Checks {
			if check.Status == "failed" {
				status.Health.Status = "degraded"
				break
			}
		}
	} else {
		status.Health.Status = "not_configured"
	}

	return status, nil
}
