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
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
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
	SaltConfig    map[string]string `json:"salt_config"`
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

// captureNodeState captures current node configuration
func (c *Checkpoint) captureNodeState(rc *eos_io.RuntimeContext) error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to get hostname: %w", err)
	}

	c.NodeState.Hostname = hostname

	// Get current role from grains if available
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "grains.get", "role"},
		Capture: true,
	})
	if err == nil {
		c.NodeState.Role = output
	}

	// Check if part of cluster
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "salt-minion"},
		Capture: true,
	})
	c.NodeState.ClusterMember = (err == nil && output == "active")

	// Capture Salt configuration
	c.NodeState.SaltConfig = make(map[string]string)
	if _, err := os.Stat("/etc/salt/minion"); err == nil {
		// Read Salt minion config (simplified)
		content, err := os.ReadFile("/etc/salt/minion")
		if err == nil {
			c.NodeState.SaltConfig["minion"] = string(content)
		}
	}

	return nil
}

// captureServiceStates captures current service states
func (c *Checkpoint) captureServiceStates(rc *eos_io.RuntimeContext) error {
	// Services to track
	services := []string{
		"salt-master",
		"salt-minion", 
		"docker",
		"postgresql",
		"vault",
		"nomad",
		"eos-storage-monitor",
	}

	for _, service := range services {
		info := ServiceInfo{Name: service}

		// Check if active
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", service},
			Capture: true,
		})
		info.Active = (err == nil && output == "active")

		// Check if enabled
		output, err = execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-enabled", service},
			Capture: true,
		})
		info.Enabled = (err == nil && output == "enabled")

		c.Services[service] = info
	}

	return nil
}

// backupFiles backs up critical configuration files
func (c *Checkpoint) backupFiles(_ *eos_io.RuntimeContext) error {
	// Files to backup
	files := []string{
		"/etc/salt/minion",
		"/etc/salt/master",
		"/etc/eos/cluster.yaml",
		"/etc/eos/storage-ops.yaml",
		"/etc/systemd/system/eos-storage-monitor.service",
	}

	// Ensure backup directory exists
	backupDir := filepath.Join(CheckpointDir, c.ID, "files")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	for _, filePath := range files {
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			continue // Skip files that don't exist
		}

		// Copy file to backup location
		backupPath := filepath.Join(backupDir, filepath.Base(filePath))
		if err := copyFile(filePath, backupPath); err != nil {
			continue // Log but don't fail
		}

		// Get file info
		stat, _ := os.Stat(filePath)
		backup := FileBackup{
			OriginalPath: filePath,
			BackupPath:   backupPath,
			Timestamp:    time.Now(),
			Size:         stat.Size(),
		}

		c.Files[filePath] = backup
	}

	return nil
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
	execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Capture: false,
	})

	logger.Info("Rollback completed", zap.String("checkpoint_id", checkpointID))
	return nil
}

// rollbackServices restores service states
func (c *Checkpoint) rollbackServices(rc *eos_io.RuntimeContext) error {
	for serviceName, serviceInfo := range c.Services {
		// If service was not active, stop it
		if !serviceInfo.Active {
			execute.Run(rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"stop", serviceName},
				Capture: false,
			})
		}

		// If service was not enabled, disable it
		if !serviceInfo.Enabled {
			execute.Run(rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"disable", serviceName},
				Capture: false,
			})
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

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	sourceInfo, err := sourceFile.Stat()
	if err != nil {
		return err
	}

	err = destFile.Chmod(sourceInfo.Mode())
	if err != nil {
		return err
	}

	_, err = io.Copy(destFile, sourceFile)
	return err
}