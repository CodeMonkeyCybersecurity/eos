// pkg/system_config/manager.go
package system_config

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SystemConfigManager provides centralized system configuration management
type SystemConfigManager struct {
	managers map[ConfigurationType]ConfigurationManager
}

// NewSystemConfigManager creates a new SystemConfigManager instance
func NewSystemConfigManager() *SystemConfigManager {
	return &SystemConfigManager{
		managers: make(map[ConfigurationType]ConfigurationManager),
	}
}

// RegisterManager registers a configuration manager for a specific type
func (scm *SystemConfigManager) RegisterManager(configType ConfigurationType, manager ConfigurationManager) {
	scm.managers[configType] = manager
}

// GetManager retrieves a configuration manager for a specific type
func (scm *SystemConfigManager) GetManager(configType ConfigurationType) (ConfigurationManager, error) {
	manager, exists := scm.managers[configType]
	if !exists {
		return nil, fmt.Errorf("no manager registered for configuration type: %s", configType)
	}
	return manager, nil
}

// ApplyConfiguration applies a configuration using the appropriate manager
func (scm *SystemConfigManager) ApplyConfiguration(rc *eos_io.RuntimeContext, options *ConfigurationOptions) (*ConfigurationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Applying system configuration",
		zap.String("type", string(options.Type)),
		zap.Bool("dry_run", options.DryRun))

	manager, err := scm.GetManager(options.Type)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	result := &ConfigurationResult{
		Type:      options.Type,
		Timestamp: start,
		Steps:     make([]ConfigurationStep, 0),
		Changes:   make([]ConfigurationChange, 0),
		Warnings:  make([]string, 0),
	}

	// Validation step
	if options.Validate {
		validationStep := ConfigurationStep{
			Name:        "Validation",
			Description: "Validating configuration parameters",
			Status:      "running",
		}
		stepStart := time.Now()

		if err := manager.Validate(); err != nil {
			validationStep.Status = "failed"
			validationStep.Error = err.Error()
			validationStep.Duration = time.Since(stepStart)
			result.Steps = append(result.Steps, validationStep)
			result.Success = false
			result.Error = fmt.Sprintf("validation failed: %v", err)
			result.Duration = time.Since(start)
			return result, err
		}

		validationStep.Status = "completed"
		validationStep.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, validationStep)
	}

	// Backup step
	if options.Backup && !options.DryRun {
		backupStep := ConfigurationStep{
			Name:        "Backup",
			Description: "Creating configuration backup",
			Status:      "running",
		}
		stepStart := time.Now()

		backup, err := manager.Backup()
		if err != nil {
			backupStep.Status = "failed"
			backupStep.Error = err.Error()
			backupStep.Duration = time.Since(stepStart)
			result.Steps = append(result.Steps, backupStep)
			logger.Warn("Backup failed, continuing with configuration", zap.Error(err))
			result.Warnings = append(result.Warnings, fmt.Sprintf("Backup failed: %v", err))
		} else {
			result.Backup = backup
			backupStep.Status = "completed"
			backupStep.Duration = time.Since(stepStart)
			result.Steps = append(result.Steps, backupStep)
		}
	}

	// Apply configuration
	applyStep := ConfigurationStep{
		Name:        "Apply Configuration",
		Description: "Applying system configuration changes",
		Status:      "running",
	}
	stepStart := time.Now()

	applyResult, err := manager.Apply()
	if err != nil {
		applyStep.Status = "failed"
		applyStep.Error = err.Error()
		applyStep.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, applyStep)
		result.Success = false
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}

	applyStep.Status = "completed"
	applyStep.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, applyStep)

	// Merge results
	result.Success = applyResult.Success
	result.Message = applyResult.Message
	result.Changes = append(result.Changes, applyResult.Changes...)
	result.Warnings = append(result.Warnings, applyResult.Warnings...)
	result.Duration = time.Since(start)

	logger.Info("Configuration applied successfully",
		zap.String("type", string(options.Type)),
		zap.Duration("duration", result.Duration))

	return result, nil
}

// GetConfigurationStatus retrieves the status of a configuration
func (scm *SystemConfigManager) GetConfigurationStatus(rc *eos_io.RuntimeContext, configType ConfigurationType) (*ConfigurationStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Getting configuration status", zap.String("type", string(configType)))

	manager, err := scm.GetManager(configType)
	if err != nil {
		return nil, err
	}

	return manager.Status()
}

// ListAvailableConfigurations returns a list of available configuration types
func (scm *SystemConfigManager) ListAvailableConfigurations() []ConfigurationType {
	types := make([]ConfigurationType, 0, len(scm.managers))
	for configType := range scm.managers {
		types = append(types, configType)
	}
	return types
}

// Utility functions for common operations

// RunCommand executes a system command with proper logging
func RunCommand(rc *eos_io.RuntimeContext, step string, command string, args ...string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing command",
		zap.String("step", step),
		zap.String("command", command),
		zap.Strings("args", args))

	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		logger.Error("Command failed",
			zap.String("step", step),
			zap.String("command", command),
			zap.String("output", string(output)),
			zap.Error(err))
		return fmt.Errorf("command failed: %w", err)
	}

	logger.Info("Command completed successfully",
		zap.String("step", step),
		zap.String("output", string(output)))

	return nil
}

// BackupFile creates a backup of a file with timestamp
func BackupFile(filePath string) (string, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "", nil // File doesn't exist, no backup needed
	}

	timestamp := time.Now().Format("20060102_150405")
	backupPath := fmt.Sprintf("%s.backup.%s", filePath, timestamp)

	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file for backup: %w", err)
	}

	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}

	return backupPath, nil
}

// EnsureDirectory creates a directory if it doesn't exist
func EnsureDirectory(dirPath string) error {
	return os.MkdirAll(dirPath, 0755)
}

// WriteFile writes content to a file with proper permissions
func WriteFile(filePath, content string, mode os.FileMode) error {
	// Ensure directory exists
	if err := EnsureDirectory(filepath.Dir(filePath)); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	return os.WriteFile(filePath, []byte(content), mode)
}

// AppendToFile appends content to a file
func AppendToFile(filePath, content string) error {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for append: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		return fmt.Errorf("failed to append to file: %w", err)
	}

	return nil
}

// CheckFileExists checks if a file exists
func CheckFileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}

// CheckServiceStatus checks if a service is active and enabled
func CheckServiceStatus(serviceName string) (ServiceState, error) {
	var state ServiceState

	// Check if service is enabled
	cmd := exec.Command("systemctl", "is-enabled", serviceName)
	if err := cmd.Run(); err == nil {
		state.Enabled = true
	}

	// Check if service is active
	cmd = exec.Command("systemctl", "is-active", serviceName)
	if err := cmd.Run(); err == nil {
		state.Active = true
	}

	return state, nil
}

// CheckPackageInstalled checks if a package is installed
func CheckPackageInstalled(packageName string) (PackageState, error) {
	var state PackageState

	cmd := exec.Command("dpkg", "-l", packageName)
	output, err := cmd.Output()
	if err == nil && strings.Contains(string(output), "ii  "+packageName) {
		state.Installed = true

		// Extract version
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "ii  "+packageName) {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					state.Version = fields[2]
				}
				break
			}
		}
	}

	return state, nil
}

// GenerateSecureToken generates a secure random token
func GenerateSecureToken(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	token := make([]byte, length)

	for i := range token {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		token[i] = charset[num.Int64()]
	}

	return string(token), nil
}


// CheckRoot verifies if the current user has root privileges
func CheckRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this operation requires root privileges")
	}
	return nil
}

// CheckDependencies verifies that required commands/packages are available
func CheckDependencies(dependencies []string) []DependencyStatus {
	var results []DependencyStatus

	for _, dep := range dependencies {
		status := DependencyStatus{
			Name:     dep,
			Type:     "command",
			Required: true,
		}

		if _, err := exec.LookPath(dep); err == nil {
			status.Available = true
		} else {
			status.Available = false
			status.Error = "command not found"
		}

		results = append(results, status)
	}

	return results
}
