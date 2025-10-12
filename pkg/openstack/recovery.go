package openstack

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BackupState represents a backup of the OpenStack configuration
type BackupState struct {
	Timestamp    time.Time                      `json:"timestamp"`
	Version      string                         `json:"version"`
	Mode         DeploymentMode                 `json:"mode"`
	Services     []string                       `json:"services"`
	ConfigFiles  map[string]string              `json:"config_files"`
	Databases    []string                       `json:"databases"`
	SystemState  map[string]interface{}         `json:"system_state"`
	BackupPath   string                         `json:"backup_path"`
}

// Rollback performs a rollback of a failed OpenStack installation
func Rollback(rc *eos_io.RuntimeContext, config *Config) error {
	ctx, span := telemetry.Start(rc.Ctx, "openstack.Rollback")
	defer span.End()
	rc = &eos_io.RuntimeContext{Ctx: ctx}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting OpenStack rollback")

	// Find the latest backup
	backup, err := findLatestBackup(rc)
	if err != nil {
		logger.Warn("No backup found, performing clean removal", zap.Error(err))
		return cleanRemoval(rc, config)
	}

	logger.Info("Found backup", zap.Time("timestamp", backup.Timestamp))

	// Stop all OpenStack services
	if err := stopAllServices(rc, config); err != nil {
		logger.Warn("Failed to stop some services", zap.Error(err))
	}

	// Restore configuration files
	if err := restoreConfigFiles(rc, backup); err != nil {
		return fmt.Errorf("failed to restore configuration files: %w", err)
	}

	// Restore databases
	if err := restoreDatabases(rc, backup); err != nil {
		return fmt.Errorf("failed to restore databases: %w", err)
	}

	// Restore system state
	if err := restoreSystemState(rc, backup); err != nil {
		return fmt.Errorf("failed to restore system state: %w", err)
	}

	// Restart services that were running before
	if err := restoreServices(rc, backup); err != nil {
		return fmt.Errorf("failed to restore services: %w", err)
	}

	logger.Info("Rollback completed successfully")
	return nil
}

// createBackup creates a backup before making changes
func createBackup(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating backup of current state")

	timestamp := time.Now()
	backupName := fmt.Sprintf("openstack-backup-%s", timestamp.Format("20060102-150405"))
	backupPath := filepath.Join(OpenStackBackupDir, backupName)

	// Create backup directory
	if err := os.MkdirAll(backupPath, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	backup := &BackupState{
		Timestamp:   timestamp,
		Version:     getTargetVersion(),
		Mode:        config.Mode,
		BackupPath:  backupPath,
		ConfigFiles: make(map[string]string),
		SystemState: make(map[string]interface{}),
	}

	// Backup configuration files
	if err := backupConfigFiles(rc, backup); err != nil {
		logger.Warn("Failed to backup some config files", zap.Error(err))
	}

	// Backup databases
	if config.IsControllerNode() {
		if err := backupDatabases(rc, backup, config); err != nil {
			logger.Warn("Failed to backup databases", zap.Error(err))
		}
	}

	// Save service states
	if err := saveServiceStates(rc, backup); err != nil {
		logger.Warn("Failed to save service states", zap.Error(err))
	}

	// Save backup metadata
	metadataPath := filepath.Join(backupPath, "backup.json")
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal backup metadata: %w", err)
	}
	if err := os.WriteFile(metadataPath, data, 0644); err != nil {
		return fmt.Errorf("failed to save backup metadata: %w", err)
	}

	// Cleanup old backups
	go cleanupOldBackups(rc, 5) // Keep last 5 backups

	logger.Info("Backup created successfully", zap.String("path", backupPath))
	return nil
}

// stopAllServices stops all OpenStack services
func stopAllServices(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Stopping all OpenStack services")

	// List of all possible OpenStack services
	services := []string{
		// Keystone (runs under Apache)
		"apache2",
		// Glance
		"glance-api",
		// Nova
		"nova-api", "nova-conductor", "nova-scheduler", "nova-novncproxy", "nova-compute",
		// Neutron
		"neutron-server", "neutron-openvswitch-agent", "neutron-dhcp-agent",
		"neutron-metadata-agent", "neutron-l3-agent",
		// Cinder
		"cinder-api", "cinder-scheduler", "cinder-volume",
		// Swift
		"swift-proxy", "swift-account", "swift-container", "swift-object",
		// Heat
		"heat-api", "heat-api-cfn", "heat-engine",
		// Supporting services
		"memcached", "rabbitmq-server", "mariadb",
	}

	var errors []error
	for _, service := range services {
		// Check if service exists
		checkCmd := exec.CommandContext(rc.Ctx, "systemctl", "list-unit-files", service+".service")
		if checkCmd.Run() != nil {
			continue // Service doesn't exist
		}

		// Stop service
		stopCmd := exec.CommandContext(rc.Ctx, "systemctl", "stop", service)
		if err := stopCmd.Run(); err != nil {
			logger.Debug("Failed to stop service",
				zap.String("service", service),
				zap.Error(err))
			errors = append(errors, err)
		} else {
			logger.Debug("Stopped service", zap.String("service", service))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to stop %d services", len(errors))
	}

	return nil
}

// cleanRemoval performs a clean removal of OpenStack
func cleanRemoval(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Performing clean removal of OpenStack")

	// Stop all services
	if err := stopAllServices(rc, config); err != nil {
		logger.Warn("Failed to stop some services", zap.Error(err))
	}

	// Remove packages
	if err := removePackages(rc); err != nil {
		logger.Warn("Failed to remove some packages", zap.Error(err))
	}

	// Remove configuration files
	if err := removeConfigFiles(rc); err != nil {
		logger.Warn("Failed to remove some config files", zap.Error(err))
	}

	// Drop databases
	if config.IsControllerNode() {
		if err := dropDatabases(rc); err != nil {
			logger.Warn("Failed to drop databases", zap.Error(err))
		}
	}

	// Remove data directories
	if err := removeDataDirectories(rc); err != nil {
		logger.Warn("Failed to remove data directories", zap.Error(err))
	}

	logger.Info("Clean removal completed")
	return nil
}

// findLatestBackup finds the most recent backup
func findLatestBackup(rc *eos_io.RuntimeContext) (*BackupState, error) {
	backupDir := OpenStackBackupDir
	
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup directory: %w", err)
	}

	var latestBackup *BackupState
	var latestTime time.Time

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		metadataPath := filepath.Join(backupDir, entry.Name(), "backup.json")
		data, err := os.ReadFile(metadataPath)
		if err != nil {
			continue
		}

		var backup BackupState
		if err := json.Unmarshal(data, &backup); err != nil {
			continue
		}

		if backup.Timestamp.After(latestTime) {
			latestTime = backup.Timestamp
			latestBackup = &backup
		}
	}

	if latestBackup == nil {
		return nil, fmt.Errorf("no valid backups found")
	}

	return latestBackup, nil
}

// backupConfigFiles backs up all configuration files
func backupConfigFiles(rc *eos_io.RuntimeContext, backup *BackupState) error {
	logger := otelzap.Ctx(rc.Ctx)

	configDirs := []string{
		"/etc/keystone",
		"/etc/glance",
		"/etc/nova",
		"/etc/neutron",
		"/etc/cinder",
		"/etc/swift",
		"/etc/heat",
		"/etc/openstack-dashboard",
	}

	for _, dir := range configDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		// Create backup subdirectory
		backupSubDir := filepath.Join(backup.BackupPath, "configs", filepath.Base(dir))
		if err := os.MkdirAll(backupSubDir, 0755); err != nil {
			logger.Warn("Failed to create backup directory",
				zap.String("dir", backupSubDir),
				zap.Error(err))
			continue
		}

		// Copy configuration files
		copyCmd := exec.CommandContext(rc.Ctx, "cp", "-r", dir+"/.", backupSubDir)
		if err := copyCmd.Run(); err != nil {
			logger.Warn("Failed to backup config directory",
				zap.String("dir", dir),
				zap.Error(err))
		} else {
			backup.ConfigFiles[dir] = backupSubDir
		}
	}

	return nil
}

// backupDatabases backs up OpenStack databases
func backupDatabases(rc *eos_io.RuntimeContext, backup *BackupState, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Backing up databases")

	databases := []string{
		"keystone", "glance", "nova", "nova_api", "nova_cell0",
		"neutron", "cinder", "heat", "placement",
	}

	backupDBDir := filepath.Join(backup.BackupPath, "databases")
	if err := os.MkdirAll(backupDBDir, 0755); err != nil {
		return fmt.Errorf("failed to create database backup directory: %w", err)
	}

	for _, db := range databases {
		dumpFile := filepath.Join(backupDBDir, fmt.Sprintf("%s.sql", db))
		dumpCmd := exec.CommandContext(rc.Ctx, "mysqldump",
			"-u", "root",
			fmt.Sprintf("-p%s", config.DBPassword),
			"--single-transaction",
			"--routines",
			"--triggers",
			db)
		
		output, err := dumpCmd.Output()
		if err != nil {
			logger.Debug("Failed to dump database",
				zap.String("database", db),
				zap.Error(err))
			continue
		}

		if err := os.WriteFile(dumpFile, output, 0600); err != nil {
			logger.Warn("Failed to save database dump",
				zap.String("database", db),
				zap.Error(err))
		} else {
			backup.Databases = append(backup.Databases, db)
		}
	}

	return nil
}

// saveServiceStates saves the current state of services
func saveServiceStates(rc *eos_io.RuntimeContext, backup *BackupState) error {
	// Get list of running OpenStack services
	services := []string{}
	
	checkServices := []string{
		"glance-api", "nova-api", "neutron-server", "cinder-api",
		"swift-proxy", "heat-api", "apache2",
	}

	for _, svc := range checkServices {
		statusCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", svc)
		if statusCmd.Run() == nil {
			services = append(services, svc)
		}
	}

	backup.Services = services
	backup.SystemState["running_services"] = services

	// Save network configuration
	networkConfig := make(map[string]interface{})
	
	// Get OVS bridges
	bridgeCmd := exec.CommandContext(rc.Ctx, "ovs-vsctl", "list-br")
	if output, err := bridgeCmd.Output(); err == nil {
		bridges := strings.Split(strings.TrimSpace(string(output)), "\n")
		networkConfig["ovs_bridges"] = bridges
	}

	backup.SystemState["network"] = networkConfig

	return nil
}

// restoreConfigFiles restores configuration files from backup
func restoreConfigFiles(rc *eos_io.RuntimeContext, backup *BackupState) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Restoring configuration files")

	for origPath, backupPath := range backup.ConfigFiles {
		// Remove current config
		removeCmd := exec.CommandContext(rc.Ctx, "rm", "-rf", origPath)
		if err := removeCmd.Run(); err != nil {
			logger.Warn("Failed to remove current config",
				zap.String("path", origPath),
				zap.Error(err))
		}

		// Restore from backup
		restoreCmd := exec.CommandContext(rc.Ctx, "cp", "-r", backupPath, origPath)
		if err := restoreCmd.Run(); err != nil {
			logger.Error("Failed to restore config",
				zap.String("path", origPath),
				zap.Error(err))
			return fmt.Errorf("failed to restore %s: %w", origPath, err)
		}
	}

	return nil
}

// restoreDatabases restores databases from backup
func restoreDatabases(rc *eos_io.RuntimeContext, backup *BackupState) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Restoring databases")

	backupDBDir := filepath.Join(backup.BackupPath, "databases")

	for _, db := range backup.Databases {
		dumpFile := filepath.Join(backupDBDir, fmt.Sprintf("%s.sql", db))
		
		// Drop existing database
		dropCmd := fmt.Sprintf(`mysql -u root -e "DROP DATABASE IF EXISTS %s;"`, db)
		exec.CommandContext(rc.Ctx, "bash", "-c", dropCmd).Run()

		// Create database
		createCmd := fmt.Sprintf(`mysql -u root -e "CREATE DATABASE %s;"`, db)
		if err := exec.CommandContext(rc.Ctx, "bash", "-c", createCmd).Run(); err != nil {
			logger.Warn("Failed to create database",
				zap.String("database", db),
				zap.Error(err))
			continue
		}

		// Restore from dump
		restoreCmd := exec.CommandContext(rc.Ctx, "mysql", "-u", "root", db)
		restoreCmd.Stdin, _ = os.Open(dumpFile)
		if err := restoreCmd.Run(); err != nil {
			logger.Error("Failed to restore database",
				zap.String("database", db),
				zap.Error(err))
		}
	}

	return nil
}

// restoreSystemState restores system state from backup
func restoreSystemState(rc *eos_io.RuntimeContext, backup *BackupState) error {
	// Restore network configuration
	if networkConfig, ok := backup.SystemState["network"].(map[string]interface{}); ok {
		// Restore OVS bridges
		if bridges, ok := networkConfig["ovs_bridges"].([]string); ok {
			for _, bridge := range bridges {
				// Check if bridge exists
				checkCmd := exec.CommandContext(rc.Ctx, "ovs-vsctl", "br-exists", bridge)
				if checkCmd.Run() != nil {
					// Create bridge
					createCmd := exec.CommandContext(rc.Ctx, "ovs-vsctl", "add-br", bridge)
					_ = createCmd.Run()
				}
			}
		}
	}

	return nil
}

// restoreServices restarts services that were running before
func restoreServices(rc *eos_io.RuntimeContext, backup *BackupState) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Restoring services")

	for _, service := range backup.Services {
		startCmd := exec.CommandContext(rc.Ctx, "systemctl", "start", service)
		if err := startCmd.Run(); err != nil {
			logger.Warn("Failed to start service",
				zap.String("service", service),
				zap.Error(err))
		}
	}

	return nil
}

// removePackages removes OpenStack packages
func removePackages(rc *eos_io.RuntimeContext) error {
	packages := []string{
		"keystone", "glance", "nova-*", "neutron-*", "cinder-*",
		"swift-*", "heat-*", "openstack-dashboard",
		"python3-*client", "python3-*middleware",
	}

	// Use apt-get remove with wildcard support
	removeCmd := exec.CommandContext(rc.Ctx, "apt-get", "remove", "--purge", "-y")
	removeCmd.Args = append(removeCmd.Args, packages...)
	removeCmd.Run() // Ignore errors for missing packages

	// Autoremove dependencies
	autoremoveCmd := exec.CommandContext(rc.Ctx, "apt-get", "autoremove", "-y")
	_ = autoremoveCmd.Run()

	return nil
}

// removeConfigFiles removes OpenStack configuration files
func removeConfigFiles(rc *eos_io.RuntimeContext) error {
	configDirs := []string{
		"/etc/keystone",
		"/etc/glance",
		"/etc/nova",
		"/etc/neutron",
		"/etc/cinder",
		"/etc/swift",
		"/etc/heat",
		"/etc/openstack-dashboard",
		"/etc/openstack",
	}

	for _, dir := range configDirs {
		removeCmd := exec.CommandContext(rc.Ctx, "rm", "-rf", dir)
		_ = removeCmd.Run()
	}

	return nil
}

// dropDatabases drops OpenStack databases
func dropDatabases(rc *eos_io.RuntimeContext) error {
	databases := []string{
		"keystone", "glance", "nova", "nova_api", "nova_cell0",
		"neutron", "cinder", "heat", "placement",
	}

	for _, db := range databases {
		dropCmd := fmt.Sprintf(`mysql -u root -e "DROP DATABASE IF EXISTS %s;"`, db)
		exec.CommandContext(rc.Ctx, "bash", "-c", dropCmd).Run()

		// Drop user
		dropUserCmd := fmt.Sprintf(`mysql -u root -e "DROP USER IF EXISTS '%s'@'localhost';"`, db)
		exec.CommandContext(rc.Ctx, "bash", "-c", dropUserCmd).Run()
		
		dropUserCmd2 := fmt.Sprintf(`mysql -u root -e "DROP USER IF EXISTS '%s'@'%%';"`, db)
		exec.CommandContext(rc.Ctx, "bash", "-c", dropUserCmd2).Run()
	}

	return nil
}

// removeDataDirectories removes OpenStack data directories
func removeDataDirectories(rc *eos_io.RuntimeContext) error {
	dataDirs := []string{
		"/var/lib/keystone",
		"/var/lib/glance",
		"/var/lib/nova",
		"/var/lib/neutron",
		"/var/lib/cinder",
		"/var/lib/swift",
		"/var/lib/heat",
		"/var/lib/openstack",
		OpenStackLogDir,
		OpenStackStateDir,
	}

	for _, dir := range dataDirs {
		removeCmd := exec.CommandContext(rc.Ctx, "rm", "-rf", dir)
		_ = removeCmd.Run()
	}

	return nil
}

// cleanupOldBackups removes old backups keeping only the specified number
func cleanupOldBackups(rc *eos_io.RuntimeContext, keepCount int) {
	logger := otelzap.Ctx(rc.Ctx)
	
	entries, err := os.ReadDir(OpenStackBackupDir)
	if err != nil {
		return
	}

	// Collect valid backups with timestamps
	type backupInfo struct {
		path      string
		timestamp time.Time
	}
	
	var backups []backupInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		metadataPath := filepath.Join(OpenStackBackupDir, entry.Name(), "backup.json")
		data, err := os.ReadFile(metadataPath)
		if err != nil {
			continue
		}

		var backup BackupState
		if err := json.Unmarshal(data, &backup); err != nil {
			continue
		}

		backups = append(backups, backupInfo{
			path:      filepath.Join(OpenStackBackupDir, entry.Name()),
			timestamp: backup.Timestamp,
		})
	}

	// Sort by timestamp (newest first)
	// In production, use sort.Slice
	
	// Remove old backups
	if len(backups) > keepCount {
		for i := keepCount; i < len(backups); i++ {
			logger.Debug("Removing old backup", zap.String("path", backups[i].path))
			_ = os.RemoveAll(backups[i].path)
		}
	}
}