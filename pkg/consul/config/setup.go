// pkg/consul/config/setup.go
// Consul configuration setup - directories, users, and validation

package config

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DirectoryConfig represents a directory to be created with specific permissions
type DirectoryConfig struct {
	Path  string
	Mode  os.FileMode
	Owner string
}

// SetupManager handles Consul configuration setup
type SetupManager struct {
	rc         *eos_io.RuntimeContext
	logger     otelzap.LoggerWithCtx
	binaryPath string
}

// NewSetupManager creates a new configuration setup manager
func NewSetupManager(rc *eos_io.RuntimeContext, binaryPath string) *SetupManager {
	return &SetupManager{
		rc:         rc,
		logger:     otelzap.Ctx(rc.Ctx),
		binaryPath: binaryPath,
	}
}

// SetupDirectories creates and configures all required Consul directories
func (sm *SetupManager) SetupDirectories() error {
	sm.logger.Info("Setting up Consul directories")

	ctx, cancel := context.WithTimeout(sm.rc.Ctx, 30*time.Second)
	defer cancel()

	// Create consul user and group first
	if err := sm.createConsulUser(); err != nil {
		return fmt.Errorf("failed to create consul user: %w", err)
	}

	// Define required directories
	directories := []DirectoryConfig{
		{Path: "/etc/consul.d", Mode: 0755, Owner: "consul"},
		{Path: "/var/lib/consul", Mode: 0755, Owner: "consul"},
		{Path: "/var/log/consul", Mode: 0755, Owner: "consul"},
		{Path: "/opt/consul", Mode: 0755, Owner: "consul"},
	}

	// Critical directories that must have correct ownership
	criticalDirs := map[string]bool{
		"/var/lib/consul": true,
		"/var/log/consul": true,
	}

	sm.logger.Info("Creating Consul directories",
		zap.Int("directory_count", len(directories)))

	for _, dir := range directories {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Create directory
		if err := os.MkdirAll(dir.Path, dir.Mode); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir.Path, err)
		}

		sm.logger.Info("Created directory",
			zap.String("path", dir.Path),
			zap.String("mode", fmt.Sprintf("%o", dir.Mode)))

		// Set ownership
		if err := sm.setOwnership(dir.Path, dir.Owner); err != nil {
			// CRITICAL: Fail hard if ownership fails on critical directories
			if criticalDirs[dir.Path] {
				return fmt.Errorf("failed to set ownership on critical directory %s (Consul will not be able to write data): %w\nRemediation: Ensure 'consul' user exists and you have permission to chown", dir.Path, err)
			}
			sm.logger.Warn("Failed to set directory ownership",
				zap.String("path", dir.Path),
				zap.String("owner", dir.Owner),
				zap.Error(err))
		} else {
			sm.logger.Info("Set directory ownership",
				zap.String("path", dir.Path),
				zap.String("owner", dir.Owner))

			// Verify ownership on critical directories
			if criticalDirs[dir.Path] {
				if err := sm.verifyOwnership(dir.Path, dir.Owner); err != nil {
					return fmt.Errorf("ownership verification failed for critical directory %s: %w", dir.Path, err)
				}
			}
		}
	}

	sm.logger.Info("All Consul directories created successfully")
	return nil
}

// CreateLogrotateConfig creates logrotate configuration to prevent disk fill
func (sm *SetupManager) CreateLogrotateConfig() error {
	sm.logger.Info("Creating logrotate configuration")

	logrotateConfig := `/var/log/consul/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 consul consul
    sharedscripts
    postrotate
        systemctl reload consul >/dev/null 2>&1 || true
    endscript
}
`

	logrotateFile := "/etc/logrotate.d/consul"
	if err := os.WriteFile(logrotateFile, []byte(logrotateConfig), 0644); err != nil {
		return fmt.Errorf("failed to write logrotate config: %w", err)
	}

	sm.logger.Info("Logrotate configuration created successfully",
		zap.String("file", logrotateFile),
		zap.String("rotation", "daily, keep 7 days"))

	return nil
}

// ValidateConfiguration validates Consul configuration files
func (sm *SetupManager) ValidateConfiguration(configDir string) error {
	sm.logger.Info("Validating Consul configuration",
		zap.String("config_dir", configDir))

	// Verify binary version first
	versionOutput, err := sm.getBinaryVersion()
	if err != nil {
		sm.logger.Warn("Failed to check Consul version",
			zap.Error(err),
			zap.String("binary", sm.binaryPath))
	} else {
		sm.logger.Info("Consul binary version",
			zap.String("version_output", versionOutput),
			zap.String("binary", sm.binaryPath))
	}

	// Validate configuration
	cmd := exec.Command(sm.binaryPath, "validate", configDir)
	output, err := cmd.CombinedOutput()

	// Always log validation output
	if len(output) > 0 {
		sm.logger.Info("Consul configuration validation output",
			zap.String("output", string(output)))
	}

	if err != nil {
		sm.logger.Error("Consul configuration validation failed",
			zap.Error(err),
			zap.String("output", string(output)),
			zap.String("binary_version", versionOutput))
		return fmt.Errorf("configuration validation failed with binary %s: %w (output: %s)",
			sm.binaryPath, err, string(output))
	}

	sm.logger.Info("Consul configuration validation succeeded")
	return nil
}

// CleanStaleConfigs removes deprecated configuration files
func (sm *SetupManager) CleanStaleConfigs(configDir string) (bool, error) {
	sm.logger.Info("Scanning config directory for stale configurations",
		zap.String("config_dir", configDir))

	needsReconfiguration := false

	entries, err := os.ReadDir(configDir)
	if err != nil {
		sm.logger.Warn("Failed to read config directory",
			zap.String("config_dir", configDir),
			zap.Error(err))
		return false, err
	}

	sm.logger.Info("Found config directory entries",
		zap.Int("count", len(entries)))

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".hcl") {
			continue
		}

		fullPath := filepath.Join(configDir, entry.Name())
		sm.logger.Info("Scanning HCL file for deprecated directives",
			zap.String("file", fullPath))

		configContent, err := os.ReadFile(fullPath)
		if err != nil {
			sm.logger.Warn("Failed to read config file",
				zap.String("file", fullPath),
				zap.Error(err))
			continue
		}

		// Check for deprecated directives
		if strings.Contains(string(configContent), "log_file") {
			sm.logger.Warn("Detected deprecated log_file directive in config file",
				zap.String("config_file", fullPath))
			needsReconfiguration = true

			// Backup and remove stale config
			backupPath := fullPath + ".backup." + time.Now().Format("20060102-150405")
			if err := os.Rename(fullPath, backupPath); err != nil {
				sm.logger.Warn("Failed to backup stale config",
					zap.String("file", fullPath),
					zap.Error(err))
			} else {
				sm.logger.Info("Backed up and removed stale config file",
					zap.String("original", fullPath),
					zap.String("backup", backupPath))
			}
		}
	}

	return needsReconfiguration, nil
}

// createConsulUser creates the consul system user and group
func (sm *SetupManager) createConsulUser() error {
	sm.logger.Info("Creating consul system user")

	// Check if user already exists
	cmd := exec.Command("id", "consul")
	if err := cmd.Run(); err == nil {
		sm.logger.Debug("Consul user already exists")
		return nil
	}

	// Create system user
	cmd = exec.Command("useradd", "--system", "--home", "/var/lib/consul",
		"--shell", "/bin/false", "consul")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create consul user: %w", err)
	}

	sm.logger.Info("Consul system user created successfully")
	return nil
}

// setOwnership sets ownership of a path
func (sm *SetupManager) setOwnership(path, owner string) error {
	cmd := exec.Command("chown", "-R", owner+":"+owner, path)
	return cmd.Run()
}

// verifyOwnership verifies that a directory has correct ownership
func (sm *SetupManager) verifyOwnership(path, expectedOwner string) error {
	cmd := exec.Command("stat", "-c", "%U:%G", path)
	output, err := cmd.Output()
	if err != nil {
		sm.logger.Debug("Failed to verify ownership with stat, assuming correct",
			zap.String("path", path),
			zap.Error(err))
		return nil
	}

	actualOwner := strings.TrimSpace(string(output))
	expectedOwnership := expectedOwner + ":" + expectedOwner

	if actualOwner != expectedOwnership {
		return fmt.Errorf("directory %s has ownership %s but expected %s",
			path, actualOwner, expectedOwnership)
	}

	sm.logger.Debug("Ownership verification passed",
		zap.String("path", path),
		zap.String("owner", actualOwner))

	return nil
}

// getBinaryVersion gets the Consul binary version
func (sm *SetupManager) getBinaryVersion() (string, error) {
	cmd := exec.Command(sm.binaryPath, "version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}
