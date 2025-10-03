// pkg/bootstrap/checkpoint.go

package bootstrap

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Checkpoint represents a system state checkpoint
type Checkpoint struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Stage       string                 `json:"stage"`
	Description string                 `json:"description"`
	NodeState   NodeState              `json:"node_state"`
	Services    map[string]ServiceInfo `json:"services"`
	Files       map[string]FileBackup  `json:"files"`
	CanRollback bool                   `json:"can_rollback"`
}

// NodeState captures the current state of the node
type NodeState struct {
	Hostname      string            `json:"hostname"`
	Role          string            `json:"role"`
	ClusterMember bool              `json:"cluster_member"`
	Config        map[string]string `json:"_config"`
	SystemdUnits  []string          `json:"systemd_units"`
}

// ServiceInfo captures service state
type ServiceInfo struct {
	Name    string `json:"name"`
	Active  bool   `json:"active"`
	Enabled bool   `json:"enabled"`
}

// FileBackup captures backed up file information
type FileBackup struct {
	OriginalPath string    `json:"original_path"`
	BackupPath   string    `json:"backup_path"`
	Timestamp    time.Time `json:"timestamp"`
	Size         int64     `json:"size"`
}

const (
	CheckpointDir = "/var/lib/eos/checkpoints"
)

// CreateCheckpoint creates a system state checkpoint
func CreateCheckpoint(rc *eos_io.RuntimeContext, stage, description string) (*Checkpoint, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating checkpoint",
		zap.String("stage", stage),
		zap.String("description", description))

	// Cleanup old checkpoints before creating new one (prevent disk fill)
	// Keep last 10 checkpoints OR 7 days, whichever is more
	if err := CleanupCheckpointsByCount(10); err != nil {
		logger.Warn("Failed to cleanup old checkpoints by count", zap.Error(err))
		// Non-fatal, continue with checkpoint creation
	}
	if err := CleanupOldCheckpoints(7 * 24 * time.Hour); err != nil {
		logger.Warn("Failed to cleanup old checkpoints by age", zap.Error(err))
		// Non-fatal, continue
	}

	checkpoint := &Checkpoint{
		ID:          fmt.Sprintf("checkpoint-%d", time.Now().Unix()),
		Timestamp:   time.Now(),
		Stage:       stage,
		Description: description,
		Services:    make(map[string]ServiceInfo),
		Files:       make(map[string]FileBackup),
		CanRollback: true,
	}

	// Capture node state
	if err := checkpoint.captureNodeState(rc); err != nil {
		return nil, fmt.Errorf("failed to capture node state: %w", err)
	}

	// Capture service states
	if err := checkpoint.captureServiceStates(rc); err != nil {
		return nil, fmt.Errorf("failed to capture service states: %w", err)
	}

	// Backup critical files
	if err := checkpoint.backupFiles(rc); err != nil {
		logger.Warn("Failed to backup some files", zap.Error(err))
		// Continue anyway, don't fail checkpoint creation
	}

	// Save checkpoint
	if err := checkpoint.save(); err != nil {
		return nil, fmt.Errorf("failed to save checkpoint: %w", err)
	}

	logger.Info("Checkpoint created successfully",
		zap.String("id", checkpoint.ID),
		zap.String("stage", stage))

	return checkpoint, nil
}

// save saves the checkpoint to disk
func (c *Checkpoint) save() error {
	// Ensure checkpoint directory exists
	if err := os.MkdirAll(CheckpointDir, 0700); err != nil {
		return fmt.Errorf("failed to create checkpoint directory: %w", err)
	}

	// Save checkpoint metadata
	checkpointPath := filepath.Join(CheckpointDir, c.ID+".json")
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %w", err)
	}

	if err := os.WriteFile(checkpointPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write checkpoint: %w", err)
	}

	return nil
}

// RollbackToCheckpoint rolls back to a previous checkpoint
func RollbackToCheckpoint(rc *eos_io.RuntimeContext, checkpointID string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting rollback", zap.String("checkpoint_id", checkpointID))

	// Load checkpoint
	checkpoint, err := LoadCheckpoint(checkpointID)
	if err != nil {
		return fmt.Errorf("failed to load checkpoint: %w", err)
	}

	if !checkpoint.CanRollback {
		return fmt.Errorf("checkpoint %s is not rollbackable", checkpointID)
	}

	// Stop services that were not running
	if err := checkpoint.rollbackServices(rc); err != nil {
		logger.Error("Failed to rollback services", zap.Error(err))
		// Continue with file rollback
	}

	// Restore files
	if err := checkpoint.rollbackFiles(); err != nil {
		logger.Error("Failed to rollback files", zap.Error(err))
		// Continue anyway
	}

	// Reload systemd
	if err := SystemctlDaemonReload(rc); err != nil {
		logger.Warn("Failed to reload systemd after rollback", zap.Error(err))
	}

	logger.Info("Rollback completed", zap.String("checkpoint_id", checkpointID))
	return nil
}

// rollbackServices restores service states
func (c *Checkpoint) rollbackServices(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	for serviceName, serviceInfo := range c.Services {
		// If service was not active, stop it
		if !serviceInfo.Active {
			logger.Info("Stopping service for rollback",
				zap.String("service", serviceName))

			if err := SystemctlStop(rc, serviceName); err != nil {
				logger.Warn("Failed to stop service during rollback",
					zap.String("service", serviceName),
					zap.Error(err))
			} else {
				// CRITICAL: Wait for service to actually stop before continuing
				// This prevents race condition where service is still writing config
				// while we're trying to restore old config
				deadline := time.Now().Add(10 * time.Second)
				stopped := false

				for time.Now().Before(deadline) {
					active, err := SystemctlIsActive(rc, serviceName)
					if err != nil || !active {
						stopped = true
						logger.Info("Service stopped successfully for rollback",
							zap.String("service", serviceName))
						break
					}
					time.Sleep(500 * time.Millisecond)
				}

				if !stopped {
					logger.Error("Service failed to stop within timeout during rollback",
						zap.String("service", serviceName),
						zap.Duration("timeout", 10*time.Second))
					// Continue anyway - rollback is best-effort
				}
			}
		}

		// If service was not enabled, disable it
		if !serviceInfo.Enabled {
			if err := SystemctlDisable(rc, serviceName); err != nil {
				logger.Warn("Failed to disable service during rollback",
					zap.String("service", serviceName),
					zap.Error(err))
			}
		}
	}

	return nil
}

// rollbackFiles restores backed up files
func (c *Checkpoint) rollbackFiles() error {
	for _, backup := range c.Files {
		if err := copyFile(backup.BackupPath, backup.OriginalPath); err != nil {
			return fmt.Errorf("failed to restore %s: %w", backup.OriginalPath, err)
		}
	}

	return nil
}

// LoadCheckpoint loads a checkpoint from disk
func LoadCheckpoint(checkpointID string) (*Checkpoint, error) {
	checkpointPath := filepath.Join(CheckpointDir, checkpointID+".json")

	data, err := os.ReadFile(checkpointPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read checkpoint: %w", err)
	}

	var checkpoint Checkpoint
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		return nil, fmt.Errorf("failed to unmarshal checkpoint: %w", err)
	}

	return &checkpoint, nil
}

// ListCheckpoints returns available checkpoints
func ListCheckpoints() ([]*Checkpoint, error) {
	if _, err := os.Stat(CheckpointDir); os.IsNotExist(err) {
		return []*Checkpoint{}, nil
	}

	entries, err := os.ReadDir(CheckpointDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read checkpoint directory: %w", err)
	}

	var checkpoints []*Checkpoint
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			checkpointID := entry.Name()[:len(entry.Name())-5] // Remove .json
			checkpoint, err := LoadCheckpoint(checkpointID)
			if err != nil {
				continue // Skip invalid checkpoints
			}
			checkpoints = append(checkpoints, checkpoint)
		}
	}

	return checkpoints, nil
}

// CleanupOldCheckpoints removes checkpoints older than the specified duration
// This prevents disk fill from accumulated checkpoints
func CleanupOldCheckpoints(maxAge time.Duration) error {
	checkpoints, err := ListCheckpoints()
	if err != nil {
		return fmt.Errorf("failed to list checkpoints: %w", err)
	}

	now := time.Now()
	removedCount := 0

	for _, checkpoint := range checkpoints {
		age := now.Sub(checkpoint.Timestamp)
		if age > maxAge {
			// Remove checkpoint JSON file
			checkpointPath := filepath.Join(CheckpointDir, checkpoint.ID+".json")
			if err := os.Remove(checkpointPath); err != nil {
				// Log but continue with other checkpoints
				continue
			}

			// Remove checkpoint backup directory
			backupDir := filepath.Join(CheckpointDir, checkpoint.ID+"-files")
			if err := os.RemoveAll(backupDir); err != nil {
				// Log but continue
				continue
			}

			removedCount++
		}
	}

	return nil
}

// CleanupCheckpointsByCount keeps only the N most recent checkpoints
func CleanupCheckpointsByCount(keepCount int) error {
	checkpoints, err := ListCheckpoints()
	if err != nil {
		return fmt.Errorf("failed to list checkpoints: %w", err)
	}

	if len(checkpoints) <= keepCount {
		return nil // Nothing to clean up
	}

	// Sort by timestamp (newest first)
	// Simple bubble sort since we don't have many checkpoints
	for i := 0; i < len(checkpoints); i++ {
		for j := i + 1; j < len(checkpoints); j++ {
			if checkpoints[j].Timestamp.After(checkpoints[i].Timestamp) {
				checkpoints[i], checkpoints[j] = checkpoints[j], checkpoints[i]
			}
		}
	}

	// Remove checkpoints beyond keepCount
	for i := keepCount; i < len(checkpoints); i++ {
		checkpoint := checkpoints[i]

		// Remove checkpoint JSON
		checkpointPath := filepath.Join(CheckpointDir, checkpoint.ID+".json")
		_ = os.Remove(checkpointPath)

		// Remove backup directory
		backupDir := filepath.Join(CheckpointDir, checkpoint.ID+"-files")
		_ = os.RemoveAll(backupDir)
	}

	return nil
}

// copyFile copies a file from src to dst (deprecated - use atomicCopyFile)
func copyFile(src, dst string) error {
	return atomicCopyFile(src, dst)
}

// atomicCopyFile copies a file atomically using temp file + rename
// This prevents partial writes on crash/power loss
func atomicCopyFile(src, dst string) error {
	// Open source file
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source: %w", err)
	}
	defer func() { _ = sourceFile.Close() }()

	// Get source file info for permissions
	sourceInfo, err := sourceFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat source: %w", err)
	}

	// Create temp file in same directory as destination (for atomic rename)
	dstDir := filepath.Dir(dst)
	tmpFile, err := os.CreateTemp(dstDir, ".checkpoint-tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Cleanup temp file on error
	success := false
	defer func() {
		if !success {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	// Set correct permissions on temp file
	if err := tmpFile.Chmod(sourceInfo.Mode()); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Copy contents to temp file
	if _, err := io.Copy(tmpFile, sourceFile); err != nil {
		return fmt.Errorf("failed to copy data: %w", err)
	}

	// Sync to disk before rename (ensure data is written)
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	// Close temp file before rename
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Atomic rename (POSIX guarantees atomicity)
	if err := os.Rename(tmpPath, dst); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	success = true
	return nil
}

// captureNodeState captures the current node state for the checkpoint
func (c *Checkpoint) captureNodeState(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Capturing node state for checkpoint")

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Capture basic node information
	c.NodeState = NodeState{
		Hostname:      hostname,
		Role:          "node", // Default role
		ClusterMember: false,
		Config:        make(map[string]string), // Empty for HashiCorp migration
		SystemdUnits:  []string{"consul", "nomad", "vault"},
	}

	logger.Debug("Node state captured successfully")
	return nil
}

// captureServiceStates captures the current state of HashiCorp services
func (c *Checkpoint) captureServiceStates(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Capturing service states for checkpoint")

	if c.Services == nil {
		c.Services = make(map[string]ServiceInfo)
	}

	// Capture HashiCorp services (replacing  services)
	services := []string{"consul", "nomad", "vault"}

	for _, service := range services {
		serviceInfo := ServiceInfo{
			Name:    service,
			Active:  false,
			Enabled: false,
		}

		// Check if service is running using systemctl
		if isServiceRunning(rc, service) {
			serviceInfo.Active = true
		}

		c.Services[service] = serviceInfo
	}

	logger.Debug("Service states captured successfully", zap.Int("services", len(c.Services)))
	return nil
}

// backupFiles creates backups of critical configuration files
func (c *Checkpoint) backupFiles(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Backing up critical files for checkpoint")

	if c.Files == nil {
		c.Files = make(map[string]FileBackup)
	}

	// Create checkpoint backup directory
	checkpointBackupDir := filepath.Join(CheckpointDir, c.ID+"-files")
	if err := os.MkdirAll(checkpointBackupDir, 0700); err != nil {
		return fmt.Errorf("failed to create checkpoint backup directory: %w", err)
	}

	// HashiCorp configuration files (replacing  files)
	criticalFiles := []string{
		"/etc/consul.d/consul.hcl",   // Consul config is in consul.d/
		"/etc/nomad.d/nomad.hcl",     // Nomad config is in nomad.d/
		"/etc/vault.d/vault.hcl",     // Vault config is in vault.d/
	}

	for _, filePath := range criticalFiles {
		if _, err := os.Stat(filePath); err == nil {
			// File exists, create backup with actual file copy
			backupPath := filepath.Join(checkpointBackupDir, filepath.Base(filePath))

			backup := FileBackup{
				OriginalPath: filePath,
				BackupPath:   backupPath,
				Timestamp:    time.Now(),
				Size:         0,
			}

			// Get file info
			if info, err := os.Stat(filePath); err == nil {
				backup.Size = info.Size()
				backup.Timestamp = info.ModTime()
			}

			// CRITICAL: Actually copy the file contents (was missing before!)
			// Use atomic copy to prevent partial writes
			if err := atomicCopyFile(filePath, backupPath); err != nil {
				logger.Error("Failed to backup file",
					zap.String("file", filePath),
					zap.Error(err))
				return fmt.Errorf("failed to backup critical file %s: %w", filePath, err)
			}

			logger.Debug("Backed up file successfully",
				zap.String("source", filePath),
				zap.String("backup", backupPath),
				zap.Int64("size", backup.Size))

			c.Files[filePath] = backup
		}
	}

	logger.Debug("File backup completed", zap.Int("files", len(c.Files)))
	return nil
}
