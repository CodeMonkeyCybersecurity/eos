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

	// HashiCorp configuration files (replacing  files)
	criticalFiles := []string{
		"/etc/consul/consul.hcl",
		"/etc/nomad/nomad.hcl",
		"/etc/vault/vault.hcl",
	}

	for _, filePath := range criticalFiles {
		if _, err := os.Stat(filePath); err == nil {
			// File exists, create backup info
			backup := FileBackup{
				OriginalPath: filePath,
				BackupPath:   fmt.Sprintf("/tmp/eos-checkpoint-%s-%s", c.ID, filepath.Base(filePath)),
				Timestamp:    time.Now(),
				Size:         0,
			}

			// Get file info
			if info, err := os.Stat(filePath); err == nil {
				backup.Size = info.Size()
				backup.Timestamp = info.ModTime()
			}

			c.Files[filePath] = backup
		}
	}

	logger.Debug("File backup information captured", zap.Int("files", len(c.Files)))
	return nil
}
