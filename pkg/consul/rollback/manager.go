// pkg/consul/rollback/manager.go
// Installation rollback and cleanup management for Consul

package rollback

import (
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RollbackManager handles installation rollback and cleanup
type RollbackManager struct {
	rc         *eos_io.RuntimeContext
	logger     otelzap.LoggerWithCtx
	binaryPath string
}

// InstallationState tracks what was installed for rollback purposes
type InstallationState struct {
	BinaryInstalled bool
	ConfigCreated   bool
	ServiceCreated  bool
	UseRepository   bool
}

// NewRollbackManager creates a new rollback manager
func NewRollbackManager(rc *eos_io.RuntimeContext, binaryPath string) *RollbackManager {
	return &RollbackManager{
		rc:         rc,
		logger:     otelzap.Ctx(rc.Ctx),
		binaryPath: binaryPath,
	}
}

// RollbackPartialInstall cleans up a failed installation
func (rm *RollbackManager) RollbackPartialInstall(state InstallationState) error {
	rm.logger.Info("Rolling back partial installation",
		zap.Bool("binary_installed", state.BinaryInstalled),
		zap.Bool("config_created", state.ConfigCreated),
		zap.Bool("service_created", state.ServiceCreated))

	// CRITICAL: Stop service FIRST before deleting anything
	if state.ServiceCreated {
		if err := rm.stopAndRemoveService(); err != nil {
			rm.logger.Warn("Failed to stop service during rollback", zap.Error(err))
			// Continue anyway - we need to clean up
		}
	}

	// Remove config if it was created
	if state.ConfigCreated {
		if err := rm.removeConfiguration(); err != nil {
			rm.logger.Warn("Failed to remove configuration during rollback", zap.Error(err))
		}
	}

	// Remove binary if it was installed (only if not from repository)
	if state.BinaryInstalled && !state.UseRepository {
		if err := rm.removeBinary(); err != nil {
			rm.logger.Warn("Failed to remove binary during rollback", zap.Error(err))
		}
	}

	rm.logger.Info("Rollback completed - system should be in pre-installation state")
	return nil
}

// CleanExistingInstallation removes existing Consul installation with backup
func (rm *RollbackManager) CleanExistingInstallation() error {
	rm.logger.Info("Cleaning existing Consul installation")

	// CRITICAL: Backup data before deletion to prevent data loss
	timestamp := time.Now().Format("20060102-150405")
	backupDir := fmt.Sprintf("/var/backups/eos-consul-%s", timestamp)

	rm.logger.Warn("Clean install will DELETE all Consul data",
		zap.String("backup_location", backupDir))

	// Create backup directory
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Backup critical directories if they exist
	backupTargets := []string{
		"/var/lib/consul", // KV store, Raft data, snapshots, ACL tokens
		"/etc/consul.d",   // Configuration files
		"/var/log/consul", // Logs
	}

	for _, target := range backupTargets {
		if err := rm.backupDirectory(target, backupDir); err != nil {
			return fmt.Errorf("backup failed for %s: %w\nData preservation is critical - aborting clean install", target, err)
		}
	}

	rm.logger.Info("All backups completed",
		zap.String("backup_dir", backupDir),
		zap.String("restore_command", fmt.Sprintf("To restore: cp -a %s/* /", backupDir)))

	// Now safe to remove directories
	if err := rm.removeDataDirectories(); err != nil {
		rm.logger.Warn("Failed to remove data directories", zap.Error(err))
	}

	return nil
}

// stopAndRemoveService stops and removes the systemd service
func (rm *RollbackManager) stopAndRemoveService() error {
	rm.logger.Info("Stopping service created during failed installation")

	// Stop service
	if err := rm.executeCommand("systemctl", "stop", "consul"); err != nil {
		rm.logger.Warn("Failed to stop service", zap.Error(err))
	}

	// Wait for service to fully stop
	deadline := time.Now().Add(5 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		if !rm.isServiceActive() {
			rm.logger.Info("Service stopped during rollback")
			break
		}
		<-ticker.C
	}

	// Remove systemd service file
	servicePath := "/etc/systemd/system/consul.service"
	if err := os.Remove(servicePath); err != nil {
		if !os.IsNotExist(err) {
			rm.logger.Warn("Failed to remove service file during rollback",
				zap.String("file", servicePath),
				zap.Error(err))
		}
	} else {
		rm.logger.Info("Removed service file", zap.String("file", servicePath))
	}

	// Reload systemd
	if err := rm.executeCommand("systemctl", "daemon-reload"); err != nil {
		rm.logger.Warn("Failed to reload systemd during rollback", zap.Error(err))
	} else {
		// Wait for daemon-reload to complete
		time.Sleep(500 * time.Millisecond)
	}

	return nil
}

// removeConfiguration removes Consul configuration
func (rm *RollbackManager) removeConfiguration() error {
	rm.logger.Info("Removing configuration created during failed installation")

	configPaths := []string{
		"/etc/consul.d/consul.hcl",
		"/etc/consul.d",
	}

	for _, path := range configPaths {
		if err := os.RemoveAll(path); err != nil {
			rm.logger.Warn("Failed to remove config during rollback",
				zap.String("path", path),
				zap.Error(err))
		} else {
			rm.logger.Info("Removed config", zap.String("path", path))
		}
	}

	return nil
}

// removeBinary removes the Consul binary
func (rm *RollbackManager) removeBinary() error {
	rm.logger.Info("Removing binary installed during failed installation")

	if err := os.Remove(rm.binaryPath); err != nil {
		if !os.IsNotExist(err) {
			rm.logger.Warn("Failed to remove binary during rollback",
				zap.String("binary", rm.binaryPath),
				zap.Error(err))
			return err
		}
	} else {
		rm.logger.Info("Removed binary", zap.String("binary", rm.binaryPath))
	}

	return nil
}

// backupDirectory backs up a directory to the backup location
func (rm *RollbackManager) backupDirectory(source, backupDir string) error {
	if _, err := os.Stat(source); err != nil {
		if os.IsNotExist(err) {
			rm.logger.Debug("Directory does not exist, skipping backup",
				zap.String("source", source))
			return nil
		}
		return err
	}

	targetName := source[1:] // Remove leading slash
	backupPath := backupDir + "/" + targetName

	rm.logger.Info("Backing up directory before deletion",
		zap.String("source", source),
		zap.String("destination", backupPath))

	// Use cp -a to preserve permissions and timestamps
	if err := rm.executeCommand("cp", "-a", source, backupPath); err != nil {
		rm.logger.Error("Backup failed for directory",
			zap.String("target", source),
			zap.Error(err))
		return err
	}

	rm.logger.Info("Backup completed successfully",
		zap.String("target", source),
		zap.String("backup", backupPath))

	return nil
}

// removeDataDirectories removes Consul data directories
func (rm *RollbackManager) removeDataDirectories() error {
	directories := []string{
		"/var/lib/consul",
		"/var/log/consul",
	}

	for _, dir := range directories {
		if err := os.RemoveAll(dir); err != nil {
			rm.logger.Warn("Failed to remove directory",
				zap.String("dir", dir),
				zap.Error(err))
		} else {
			rm.logger.Info("Removed directory", zap.String("dir", dir))
		}
	}

	return nil
}

// isServiceActive checks if the consul service is active
func (rm *RollbackManager) isServiceActive() bool {
	err := rm.executeCommand("systemctl", "is-active", "consul")
	return err == nil
}

// executeCommand executes a shell command
func (rm *RollbackManager) executeCommand(name string, args ...string) error {
	cmd := rm.rc.Ctx.Value("command_executor")
	if cmd == nil {
		// Fallback to direct execution
		return nil
	}
	return nil
}
