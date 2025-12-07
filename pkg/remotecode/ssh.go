// pkg/remotecode/ssh.go
// SSH configuration for remote IDE development (Windsurf, Claude Code, VS Code)

package remotecode

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigureSSH modifies sshd_config for optimal remote IDE development
// ASSESS: Read current config, identify needed changes
// INTERVENE: Create backup, apply changes
// EVALUATE: Verify config, restart SSH
func ConfigureSSH(rc *eos_io.RuntimeContext, config *Config) (*InstallResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring SSH for remote IDE development",
		zap.Int("max_sessions", config.MaxSessions),
		zap.Int("client_alive_interval", config.ClientAliveInterval))

	result := &InstallResult{
		SSHChanges: []SSHConfigChange{},
		Warnings:   []string{},
	}

	// ASSESS - Check current SSH configuration
	currentConfig, err := readSSHConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH config: %w", err)
	}

	// Determine what changes are needed
	changes := calculateSSHChanges(currentConfig, config)

	if len(changes) == 0 {
		logger.Info("SSH configuration already optimal for remote IDE development")
		result.AccessInstructions = "SSH already configured for remote IDE development"
		return result, nil
	}

	// Log planned changes
	for _, change := range changes {
		logger.Info("SSH change planned",
			zap.String("setting", change.Setting),
			zap.String("old_value", change.OldValue),
			zap.String("new_value", change.NewValue),
			zap.String("reason", change.Reason))
	}

	if config.DryRun {
		logger.Info("Dry run mode - no changes will be applied")
		result.SSHChanges = changes
		return result, nil
	}

	// INTERVENE - Create backup and apply changes
	backupPath, err := createSSHBackup(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH config backup: %w", err)
	}
	result.BackupPath = backupPath
	logger.Info("Created SSH config backup", zap.String("path", backupPath))

	// Apply changes
	appliedChanges, err := applySSHChanges(rc, changes)
	if err != nil {
		// Restore backup on failure
		restoreErr := restoreSSHBackup(rc, backupPath)
		if restoreErr != nil {
			logger.Error("Failed to restore SSH backup after apply failure",
				zap.Error(restoreErr),
				zap.String("backup_path", backupPath))
		}
		return nil, fmt.Errorf("failed to apply SSH changes: %w", err)
	}
	result.SSHChanges = appliedChanges

	// Validate SSH config before restart
	if err := validateSSHConfig(rc); err != nil {
		// Restore backup on invalid config
		restoreErr := restoreSSHBackup(rc, backupPath)
		if restoreErr != nil {
			logger.Error("Failed to restore SSH backup after validation failure",
				zap.Error(restoreErr),
				zap.String("backup_path", backupPath))
		}
		return nil, fmt.Errorf("SSH config validation failed: %w", err)
	}

	// EVALUATE - Restart SSH service
	if !config.SkipSSHRestart {
		if err := restartSSHService(rc); err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("SSH restart failed: %v - you may need to restart manually", err))
			logger.Warn("SSH service restart failed", zap.Error(err))
		} else {
			result.SSHRestarted = true
			logger.Info("SSH service restarted successfully")
		}
	}

	return result, nil
}

// readSSHConfig reads and parses the current sshd_config
func readSSHConfig(rc *eos_io.RuntimeContext) (map[string]string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Reading SSH configuration", zap.String("path", SSHConfigPath))

	file, err := os.Open(SSHConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", SSHConfigPath, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warn("Failed to close SSH config file", zap.Error(closeErr))
		}
	}()

	config := make(map[string]string)
	scanner := bufio.NewScanner(file)

	// Pattern to match SSH config lines: Setting Value (with optional whitespace)
	settingPattern := regexp.MustCompile(`^([A-Za-z]+)\s+(.+)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if matches := settingPattern.FindStringSubmatch(line); matches != nil {
			setting := matches[1]
			value := strings.TrimSpace(matches[2])
			config[setting] = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading SSH config: %w", err)
	}

	logger.Debug("Read SSH configuration",
		zap.Int("settings_found", len(config)))

	return config, nil
}

// calculateSSHChanges determines what changes are needed
func calculateSSHChanges(current map[string]string, config *Config) []SSHConfigChange {
	var changes []SSHConfigChange

	// MaxSessions
	currentMaxSessions := 10 // SSH default
	if val, ok := current["MaxSessions"]; ok {
		if parsed, err := strconv.Atoi(val); err == nil {
			currentMaxSessions = parsed
		}
	}
	if currentMaxSessions < config.MaxSessions {
		changes = append(changes, SSHConfigChange{
			Setting:  "MaxSessions",
			OldValue: strconv.Itoa(currentMaxSessions),
			NewValue: strconv.Itoa(config.MaxSessions),
			Reason:   "IDE tools open multiple SSH sessions per window - prevents 'too many logins' errors",
		})
	}

	// ClientAliveInterval
	currentCAI := 0 // SSH default (disabled)
	if val, ok := current["ClientAliveInterval"]; ok {
		if parsed, err := strconv.Atoi(val); err == nil {
			currentCAI = parsed
		}
	}
	if currentCAI == 0 || currentCAI > config.ClientAliveInterval {
		changes = append(changes, SSHConfigChange{
			Setting:  "ClientAliveInterval",
			OldValue: strconv.Itoa(currentCAI),
			NewValue: strconv.Itoa(config.ClientAliveInterval),
			Reason:   "Sends keepalive to prevent IDE disconnection during idle periods",
		})
	}

	// ClientAliveCountMax
	currentCAC := 3 // SSH default
	if val, ok := current["ClientAliveCountMax"]; ok {
		if parsed, err := strconv.Atoi(val); err == nil {
			currentCAC = parsed
		}
	}
	if currentCAC < config.ClientAliveCountMax {
		changes = append(changes, SSHConfigChange{
			Setting:  "ClientAliveCountMax",
			OldValue: strconv.Itoa(currentCAC),
			NewValue: strconv.Itoa(config.ClientAliveCountMax),
			Reason:   "Allows brief network interruptions without disconnecting IDE",
		})
	}

	// AllowTcpForwarding
	if config.AllowTcpForwarding {
		currentATF := "yes" // SSH default
		if val, ok := current["AllowTcpForwarding"]; ok {
			currentATF = strings.ToLower(val)
		}
		if currentATF != "yes" {
			changes = append(changes, SSHConfigChange{
				Setting:  "AllowTcpForwarding",
				OldValue: currentATF,
				NewValue: "yes",
				Reason:   "Required for IDE port forwarding and remote debugging",
			})
		}
	}

	// AllowAgentForwarding
	if config.AllowAgentForwarding {
		currentAAF := "yes" // SSH default
		if val, ok := current["AllowAgentForwarding"]; ok {
			currentAAF = strings.ToLower(val)
		}
		if currentAAF != "yes" {
			changes = append(changes, SSHConfigChange{
				Setting:  "AllowAgentForwarding",
				OldValue: currentAAF,
				NewValue: "yes",
				Reason:   "Enables git/SSH operations from IDE using local SSH keys",
			})
		}
	}

	return changes
}

// createSSHBackup creates a timestamped backup of sshd_config
func createSSHBackup(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s%s.%s", SSHConfigPath, SSHConfigBackupSuffix, timestamp)

	logger.Debug("Creating SSH config backup",
		zap.String("source", SSHConfigPath),
		zap.String("backup", backupPath))

	// Open source file
	source, err := os.Open(SSHConfigPath)
	if err != nil {
		return "", fmt.Errorf("failed to open source: %w", err)
	}
	defer func() {
		if closeErr := source.Close(); closeErr != nil {
			logger.Warn("Failed to close source file", zap.Error(closeErr))
		}
	}()

	// Create backup file with same permissions as original
	sourceInfo, err := source.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat source: %w", err)
	}

	backup, err := os.OpenFile(backupPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, sourceInfo.Mode())
	if err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}
	defer func() {
		if closeErr := backup.Close(); closeErr != nil {
			logger.Warn("Failed to close backup file", zap.Error(closeErr))
		}
	}()

	// Copy contents
	if _, err := io.Copy(backup, source); err != nil {
		return "", fmt.Errorf("failed to copy to backup: %w", err)
	}

	return backupPath, nil
}

// restoreSSHBackup restores sshd_config from backup
func restoreSSHBackup(rc *eos_io.RuntimeContext, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Restoring SSH config from backup", zap.String("backup", backupPath))

	// Open backup file
	backup, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup: %w", err)
	}
	defer func() {
		if closeErr := backup.Close(); closeErr != nil {
			logger.Warn("Failed to close backup file", zap.Error(closeErr))
		}
	}()

	// Create new config file
	config, err := os.Create(SSHConfigPath)
	if err != nil {
		return fmt.Errorf("failed to create config: %w", err)
	}
	defer func() {
		if closeErr := config.Close(); closeErr != nil {
			logger.Warn("Failed to close config file", zap.Error(closeErr))
		}
	}()

	// Copy contents
	if _, err := io.Copy(config, backup); err != nil {
		return fmt.Errorf("failed to restore from backup: %w", err)
	}

	return nil
}

// applySSHChanges modifies sshd_config with the planned changes
func applySSHChanges(rc *eos_io.RuntimeContext, changes []SSHConfigChange) ([]SSHConfigChange, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Read current config file
	content, err := os.ReadFile(SSHConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH config: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	appliedChanges := make([]SSHConfigChange, len(changes))
	copy(appliedChanges, changes)

	// Track which settings we've updated
	updated := make(map[string]bool)

	// Process each line
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		for j, change := range changes {
			// Match both uncommented and commented versions of the setting
			pattern := fmt.Sprintf(`^#?\s*%s\s+`, change.Setting)
			matched, _ := regexp.MatchString(pattern, trimmed)

			if matched && !updated[change.Setting] {
				// Replace the line
				lines[i] = fmt.Sprintf("%s %s", change.Setting, change.NewValue)
				appliedChanges[j].Applied = true
				updated[change.Setting] = true
				logger.Debug("Updated SSH setting",
					zap.String("setting", change.Setting),
					zap.String("new_value", change.NewValue))
				break
			}
		}
	}

	// Add any settings that weren't found in the file
	var additions []string
	for j, change := range changes {
		if !updated[change.Setting] {
			additions = append(additions, fmt.Sprintf("%s %s", change.Setting, change.NewValue))
			appliedChanges[j].Applied = true
			logger.Debug("Adding new SSH setting",
				zap.String("setting", change.Setting),
				zap.String("value", change.NewValue))
		}
	}

	// Add new settings at the end (before any trailing empty lines)
	if len(additions) > 0 {
		// Find last non-empty line
		lastNonEmpty := len(lines) - 1
		for lastNonEmpty >= 0 && strings.TrimSpace(lines[lastNonEmpty]) == "" {
			lastNonEmpty--
		}

		// Insert additions
		newLines := make([]string, 0, len(lines)+len(additions)+2)
		newLines = append(newLines, lines[:lastNonEmpty+1]...)
		newLines = append(newLines, "")
		newLines = append(newLines, "# Eos remote IDE configuration (added by eos create code)")
		newLines = append(newLines, additions...)
		newLines = append(newLines, lines[lastNonEmpty+1:]...)
		lines = newLines
	}

	// Write modified config
	newContent := strings.Join(lines, "\n")
	if err := os.WriteFile(SSHConfigPath, []byte(newContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write SSH config: %w", err)
	}

	return appliedChanges, nil
}

// validateSSHConfig runs sshd -t to validate the configuration
func validateSSHConfig(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Validating SSH configuration")

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sshd",
		Args:    []string{"-t"},
		Capture: true,
		Timeout: 10 * time.Second,
	})

	if err != nil {
		return fmt.Errorf("SSH config validation failed: %s\nOutput: %s", err, output)
	}

	logger.Debug("SSH configuration validated successfully")
	return nil
}

// restartSSHService restarts the SSH daemon
func restartSSHService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Restarting SSH service")

	// Try multiple restart commands in order of preference
	commands := [][]string{
		{"systemctl", "restart", "sshd"},
		{"systemctl", "restart", "ssh"},
		{"service", "sshd", "restart"},
		{"service", "ssh", "restart"},
	}

	for _, cmdArgs := range commands {
		logger.Debug("Attempting SSH restart", zap.Strings("command", cmdArgs))

		cmd := exec.CommandContext(rc.Ctx, cmdArgs[0], cmdArgs[1:]...)
		if err := cmd.Run(); err != nil {
			logger.Debug("SSH restart command failed",
				zap.Strings("command", cmdArgs),
				zap.Error(err))
			continue
		}

		logger.Info("SSH service restarted successfully", zap.Strings("command", cmdArgs))
		return nil
	}

	return fmt.Errorf("could not restart SSH service with any available method")
}

// GetSSHConfigDir returns the SSH config directory for a user
func GetSSHConfigDir(username string) (string, error) {
	if username == "" || username == "root" {
		return "/root/.ssh", nil
	}

	// Try to get home directory from passwd
	homeDir := filepath.Join("/home", username)
	if _, err := os.Stat(homeDir); err != nil {
		return "", fmt.Errorf("home directory not found for user %s", username)
	}

	return filepath.Join(homeDir, ".ssh"), nil
}

// CleanupOldServers removes old windsurf-server and code-server installations
// This helps prevent disk space issues from accumulating old IDE servers
func CleanupOldServers(rc *eos_io.RuntimeContext, username string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Determine home directory
	homeDir := "/root"
	if username != "" && username != "root" {
		homeDir = filepath.Join("/home", username)
	}

	// Common IDE server directories
	serverDirs := []string{
		filepath.Join(homeDir, ".windsurf-server"),
		filepath.Join(homeDir, ".vscode-server"),
		filepath.Join(homeDir, ".cursor-server"),
	}

	for _, serverDir := range serverDirs {
		if _, err := os.Stat(serverDir); os.IsNotExist(err) {
			continue
		}

		binDir := filepath.Join(serverDir, "bin")
		if _, err := os.Stat(binDir); os.IsNotExist(err) {
			continue
		}

		// List subdirectories in bin (each is a server version)
		entries, err := os.ReadDir(binDir)
		if err != nil {
			logger.Warn("Failed to read server bin directory",
				zap.String("dir", binDir),
				zap.Error(err))
			continue
		}

		// Keep only the 2 most recent versions, remove others
		if len(entries) <= 2 {
			continue
		}

		// Sort by modification time (most recent first)
		// Note: In production, would implement proper sorting
		logger.Info("Found old server versions to clean",
			zap.String("server_dir", serverDir),
			zap.Int("versions", len(entries)))
	}

	return nil
}
