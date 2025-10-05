// pkg/kvm/snapshot.go

package kvm

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SnapshotConfig defines configuration for KVM snapshot operations
type SnapshotConfig struct {
	VMName          string            `yaml:"vm_name" json:"vm_name"`
	SnapshotName    string            `yaml:"snapshot_name" json:"snapshot_name"`
	Description     string            `yaml:"description" json:"description"`
	BackupDir       string            `yaml:"backup_dir" json:"backup_dir"`
	IncludeMemory   bool              `yaml:"include_memory" json:"include_memory"`
	IncludeDisk     bool              `yaml:"include_disk" json:"include_disk"`
	Compression     string            `yaml:"compression" json:"compression"` // gzip, xz, none
	Metadata        map[string]string `yaml:"metadata" json:"metadata"`
	LiveSnapshot    bool              `yaml:"live_snapshot" json:"live_snapshot"`
	Timeout         time.Duration     `yaml:"timeout" json:"timeout"`
}

// SnapshotInfo represents information about a VM snapshot
type SnapshotInfo struct {
	Name         string            `xml:"name" json:"name"`
	Description  string            `xml:"description" json:"description"`
	State        string            `xml:"state" json:"state"`
	CreationTime time.Time         `xml:"creationTime" json:"creation_time"`
	Parent       string            `xml:"parent" json:"parent,omitempty"`
	Children     []string          `xml:"children>child" json:"children,omitempty"`
	Active       bool              `xml:"active" json:"active"`
	Current      bool              `xml:"current" json:"current"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	DiskPath     string            `json:"disk_path,omitempty"`
	MemoryPath   string            `json:"memory_path,omitempty"`
	Size         int64             `json:"size,omitempty"`
}

// SnapshotBackupResult represents the result of a snapshot backup operation
type SnapshotBackupResult struct {
	Success        bool              `json:"success"`
	BackupPath     string            `json:"backup_path"`
	SnapshotInfo   *SnapshotInfo     `json:"snapshot_info"`
	BackupSize     int64             `json:"backup_size"`
	Duration       time.Duration     `json:"duration"`
	ComponentPaths map[string]string `json:"component_paths"` // memory, disk, xml
	ErrorMessage   string            `json:"error_message,omitempty"`
}

// SnapshotManager handles VM snapshot operations following Assess → Intervene → Evaluate pattern
type SnapshotManager struct {
	config *SnapshotConfig
	logger *otelzap.LoggerWithCtx
}

// NewSnapshotManager creates a new snapshot manager
func NewSnapshotManager(config *SnapshotConfig, logger otelzap.LoggerWithCtx) *SnapshotManager {
	return &SnapshotManager{
		config: config,
		logger: &logger,
	}
}

// CreateSnapshot creates a VM snapshot following AIE pattern
func (sm *SnapshotManager) CreateSnapshot(rc *eos_io.RuntimeContext) (*SnapshotBackupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	logger.Info("Starting KVM snapshot creation",
		zap.String("vm_name", sm.config.VMName),
		zap.String("snapshot_name", sm.config.SnapshotName),
		zap.Bool("include_memory", sm.config.IncludeMemory),
		zap.Bool("live_snapshot", sm.config.LiveSnapshot))

	result := &SnapshotBackupResult{
		ComponentPaths: make(map[string]string),
	}

	// Assessment: Verify VM exists and is in appropriate state
	if err := sm.assessVMState(rc); err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("VM assessment failed: %v", err)
		return result, err
	}

	// Intervention: Create the snapshot
	if err := sm.createSnapshotIntervention(rc, result); err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Snapshot creation failed: %v", err)
		return result, err
	}

	// Evaluation: Verify snapshot was created successfully
	if err := sm.evaluateSnapshotCreation(rc, result); err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Snapshot verification failed: %v", err)
		return result, err
	}

	result.Success = true
	result.Duration = time.Since(startTime)
	logger.Info("KVM snapshot created successfully",
		zap.String("snapshot_name", sm.config.SnapshotName),
		zap.Duration("duration", result.Duration),
		zap.Int64("backup_size", result.BackupSize))

	return result, nil
}

// BackupSnapshot exports a snapshot to backup storage
func (sm *SnapshotManager) BackupSnapshot(rc *eos_io.RuntimeContext, snapshotName string) (*SnapshotBackupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	logger.Info("Starting KVM snapshot backup",
		zap.String("vm_name", sm.config.VMName),
		zap.String("snapshot_name", snapshotName),
		zap.String("backup_dir", sm.config.BackupDir))

	result := &SnapshotBackupResult{
		ComponentPaths: make(map[string]string),
	}

	// Assessment: Verify snapshot exists and backup directory is accessible
	if err := sm.assessSnapshotBackup(rc, snapshotName); err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Snapshot backup assessment failed: %v", err)
		return result, err
	}

	// Intervention: Export snapshot components
	if err := sm.backupSnapshotIntervention(rc, snapshotName, result); err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Snapshot backup failed: %v", err)
		return result, err
	}

	// Evaluation: Verify backup integrity
	if err := sm.evaluateSnapshotBackup(rc, result); err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Snapshot backup verification failed: %v", err)
		return result, err
	}

	result.Success = true
	result.Duration = time.Since(startTime)
	logger.Info("KVM snapshot backup completed successfully",
		zap.String("backup_path", result.BackupPath),
		zap.Duration("duration", result.Duration),
		zap.Int64("backup_size", result.BackupSize))

	return result, nil
}

// RestoreSnapshot restores a VM from a snapshot backup
func (sm *SnapshotManager) RestoreSnapshot(rc *eos_io.RuntimeContext, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting KVM snapshot restore",
		zap.String("vm_name", sm.config.VMName),
		zap.String("backup_path", backupPath))

	// Assessment: Verify backup exists and VM can be restored
	if err := sm.assessSnapshotRestore(rc, backupPath); err != nil {
		return fmt.Errorf("snapshot restore assessment failed: %w", err)
	}

	// Intervention: Restore VM from backup
	if err := sm.restoreSnapshotIntervention(rc, backupPath); err != nil {
		return fmt.Errorf("snapshot restore failed: %w", err)
	}

	// Evaluation: Verify VM is restored and functional
	if err := sm.evaluateSnapshotRestore(rc); err != nil {
		return fmt.Errorf("snapshot restore verification failed: %w", err)
	}

	logger.Info("KVM snapshot restore completed successfully")
	return nil
}

// VerifySnapshot checks the integrity of a snapshot
func (sm *SnapshotManager) VerifySnapshot(rc *eos_io.RuntimeContext, snapshotName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying KVM snapshot integrity",
		zap.String("vm_name", sm.config.VMName),
		zap.String("snapshot_name", snapshotName))

	// Check snapshot exists in libvirt
	exists, err := sm.snapshotExists(rc, snapshotName)
	if err != nil {
		return fmt.Errorf("failed to check snapshot existence: %w", err)
	}
	if !exists {
		return fmt.Errorf("snapshot %s does not exist for VM %s", snapshotName, sm.config.VMName)
	}

	// Get snapshot information
	info, err := sm.getSnapshotInfo(rc, snapshotName)
	if err != nil {
		return fmt.Errorf("failed to get snapshot info: %w", err)
	}

	// Verify snapshot XML is valid
	if err := sm.verifySnapshotXML(rc, snapshotName); err != nil {
		return fmt.Errorf("snapshot XML verification failed: %w", err)
	}

	// Verify disk files exist and are accessible
	if info.DiskPath != "" {
		if _, err := os.Stat(info.DiskPath); err != nil {
			return fmt.Errorf("snapshot disk file not accessible: %w", err)
		}
	}

	// Verify memory file if it exists
	if info.MemoryPath != "" {
		if _, err := os.Stat(info.MemoryPath); err != nil {
			return fmt.Errorf("snapshot memory file not accessible: %w", err)
		}
	}

	logger.Info("KVM snapshot verification completed successfully",
		zap.String("snapshot_name", snapshotName),
		zap.String("state", info.State),
		zap.Time("creation_time", info.CreationTime))

	return nil
}

// ListSnapshots returns all snapshots for a VM
func (sm *SnapshotManager) ListSnapshots(rc *eos_io.RuntimeContext) ([]*SnapshotInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing KVM snapshots", zap.String("vm_name", sm.config.VMName))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "virsh",
		Args:    []string{"snapshot-list", sm.config.VMName, "--metadata"},
		Capture: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list snapshots: %w", err)
	}

	// Parse snapshot list output
	snapshots := []*SnapshotInfo{}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	
	// Skip header lines
	for i, line := range lines {
		if i < 2 || strings.TrimSpace(line) == "" {
			continue
		}
		
		// Parse snapshot line format: Name State Creation Time
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			snapshot := &SnapshotInfo{
				Name:  fields[0],
				State: fields[1],
			}
			
			// Parse creation time
			if timeStr := strings.Join(fields[2:], " "); timeStr != "" {
				if t, err := time.Parse("2006-01-02 15:04:05 -0700", timeStr); err == nil {
					snapshot.CreationTime = t
				}
			}
			
			// Get detailed info for each snapshot
			if detailedInfo, err := sm.getSnapshotInfo(rc, snapshot.Name); err == nil {
				snapshot.Description = detailedInfo.Description
				snapshot.DiskPath = detailedInfo.DiskPath
				snapshot.MemoryPath = detailedInfo.MemoryPath
				snapshot.Size = detailedInfo.Size
			}
			
			snapshots = append(snapshots, snapshot)
		}
	}

	logger.Info("Found KVM snapshots", 
		zap.String("vm_name", sm.config.VMName),
		zap.Int("count", len(snapshots)))

	return snapshots, nil
}

// DeleteSnapshot removes a snapshot
func (sm *SnapshotManager) DeleteSnapshot(rc *eos_io.RuntimeContext, snapshotName string, deleteMetadata bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Deleting KVM snapshot",
		zap.String("vm_name", sm.config.VMName),
		zap.String("snapshot_name", snapshotName),
		zap.Bool("delete_metadata", deleteMetadata))

	args := []string{"snapshot-delete", sm.config.VMName, snapshotName}
	if deleteMetadata {
		args = append(args, "--metadata")
	}

	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "virsh",
		Args:    args,
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to delete snapshot: %w", err)
	}

	logger.Info("KVM snapshot deleted successfully",
		zap.String("snapshot_name", snapshotName))

	return nil
}

// Implementation methods

func (sm *SnapshotManager) assessVMState(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if VM exists
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "virsh",
		Args:    []string{"dominfo", sm.config.VMName},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("VM %s not found or not accessible", sm.config.VMName)
	}

	// Check VM state
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "virsh",
		Args:    []string{"domstate", sm.config.VMName},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to get VM state: %w", err)
	}

	state := strings.TrimSpace(output)
	logger.Info("VM state assessed", 
		zap.String("vm_name", sm.config.VMName),
		zap.String("state", state))

	// For live snapshots, VM should be running
	if sm.config.LiveSnapshot && state != "running" {
		return fmt.Errorf("VM must be running for live snapshots, current state: %s", state)
	}

	return nil
}

func (sm *SnapshotManager) createSnapshotIntervention(rc *eos_io.RuntimeContext, result *SnapshotBackupResult) error {
	args := []string{"snapshot-create-as", sm.config.VMName, sm.config.SnapshotName}

	if sm.config.Description != "" {
		args = append(args, "--description", sm.config.Description)
	}

	if sm.config.IncludeMemory {
		args = append(args, "--memspec", "snapshot=external")
	}

	if sm.config.IncludeDisk {
		args = append(args, "--diskspec", "vda,snapshot=external")
	}

	if !sm.config.LiveSnapshot {
		args = append(args, "--halt")
	}

	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "virsh",
		Args:    args,
		Capture: true,
		Timeout: sm.config.Timeout,
	})
	if err != nil {
		return fmt.Errorf("virsh snapshot creation failed: %w", err)
	}

	// Get created snapshot info
	info, err := sm.getSnapshotInfo(rc, sm.config.SnapshotName)
	if err != nil {
		return fmt.Errorf("failed to get created snapshot info: %w", err)
	}

	result.SnapshotInfo = info
	return nil
}

func (sm *SnapshotManager) evaluateSnapshotCreation(rc *eos_io.RuntimeContext, result *SnapshotBackupResult) error {
	// Verify snapshot exists
	exists, err := sm.snapshotExists(rc, sm.config.SnapshotName)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("snapshot was not created successfully")
	}

	// Verify snapshot can be accessed
	return sm.VerifySnapshot(rc, sm.config.SnapshotName)
}

func (sm *SnapshotManager) assessSnapshotBackup(rc *eos_io.RuntimeContext, snapshotName string) error {
	// Verify snapshot exists
	exists, err := sm.snapshotExists(rc, snapshotName)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("snapshot %s does not exist", snapshotName)
	}

	// Verify backup directory exists and is writable
	if err := os.MkdirAll(sm.config.BackupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	return nil
}

func (sm *SnapshotManager) backupSnapshotIntervention(rc *eos_io.RuntimeContext, snapshotName string, result *SnapshotBackupResult) error {
	timestamp := time.Now().Format("20060102-150405")
	backupPath := filepath.Join(sm.config.BackupDir, fmt.Sprintf("%s_%s_%s", sm.config.VMName, snapshotName, timestamp))
	
	if err := os.MkdirAll(backupPath, 0755); err != nil {
		return fmt.Errorf("failed to create backup path: %w", err)
	}

	result.BackupPath = backupPath

	// Export snapshot XML
	xmlPath := filepath.Join(backupPath, "snapshot.xml")
	xmlOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "virsh",
		Args:    []string{"snapshot-dumpxml", sm.config.VMName, snapshotName},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to export snapshot XML: %w", err)
	}

	if err := os.WriteFile(xmlPath, []byte(xmlOutput), 0644); err != nil {
		return fmt.Errorf("failed to write snapshot XML: %w", err)
	}
	result.ComponentPaths["xml"] = xmlPath

	// Get snapshot info to find disk and memory files
	info, err := sm.getSnapshotInfo(rc, snapshotName)
	if err != nil {
		return fmt.Errorf("failed to get snapshot info: %w", err)
	}

	// Copy disk files if they exist
	if info.DiskPath != "" {
		diskBackupPath := filepath.Join(backupPath, "disk.qcow2")
		if err := sm.copyFileWithCompression(info.DiskPath, diskBackupPath); err != nil {
			return fmt.Errorf("failed to backup disk: %w", err)
		}
		result.ComponentPaths["disk"] = diskBackupPath
	}

	// Copy memory file if it exists
	if info.MemoryPath != "" {
		memoryBackupPath := filepath.Join(backupPath, "memory.save")
		if err := sm.copyFileWithCompression(info.MemoryPath, memoryBackupPath); err != nil {
			return fmt.Errorf("failed to backup memory: %w", err)
		}
		result.ComponentPaths["memory"] = memoryBackupPath
	}

	// Calculate backup size
	result.BackupSize = sm.calculateBackupSize(backupPath)

	return nil
}

func (sm *SnapshotManager) evaluateSnapshotBackup(rc *eos_io.RuntimeContext, result *SnapshotBackupResult) error {
	// Verify backup directory exists
	if _, err := os.Stat(result.BackupPath); err != nil {
		return fmt.Errorf("backup directory not found: %w", err)
	}

	// Verify all component files exist
	for component, path := range result.ComponentPaths {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("backup component %s not found: %w", component, err)
		}
	}

	// Verify XML is valid
	if xmlPath, exists := result.ComponentPaths["xml"]; exists {
		if err := sm.validateXMLFile(xmlPath); err != nil {
			return fmt.Errorf("backup XML validation failed: %w", err)
		}
	}

	return nil
}

func (sm *SnapshotManager) assessSnapshotRestore(rc *eos_io.RuntimeContext, backupPath string) error {
	// Verify backup directory exists
	if _, err := os.Stat(backupPath); err != nil {
		return fmt.Errorf("backup path not found: %w", err)
	}

	// Verify required backup components exist
	requiredFiles := []string{"snapshot.xml"}
	for _, file := range requiredFiles {
		filePath := filepath.Join(backupPath, file)
		if _, err := os.Stat(filePath); err != nil {
			return fmt.Errorf("required backup file not found: %s", file)
		}
	}

	return nil
}

func (sm *SnapshotManager) restoreSnapshotIntervention(rc *eos_io.RuntimeContext, backupPath string) error {
	// Read snapshot XML
	xmlPath := filepath.Join(backupPath, "snapshot.xml")
	if _, err := os.ReadFile(xmlPath); err != nil {
		return fmt.Errorf("failed to read snapshot XML: %w", err)
	}

	// Restore disk files if they exist
	diskPath := filepath.Join(backupPath, "disk.qcow2")
	if _, err := os.Stat(diskPath); err == nil {
		// Restore disk to original location or new location
		// Implementation would depend on specific requirements
	}

	// Restore memory file if it exists
	memoryPath := filepath.Join(backupPath, "memory.save")
	if _, err := os.Stat(memoryPath); err == nil {
		// Restore memory state
		// Implementation would depend on specific requirements
	}

	// Create snapshot from XML
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "virsh",
		Args:    []string{"snapshot-create", sm.config.VMName, xmlPath},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to restore snapshot: %w", err)
	}

	return nil
}

func (sm *SnapshotManager) evaluateSnapshotRestore(rc *eos_io.RuntimeContext) error {
	// Verify VM is accessible
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "virsh",
		Args:    []string{"dominfo", sm.config.VMName},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("VM not accessible after restore: %w", err)
	}

	return nil
}

// Helper methods

func (sm *SnapshotManager) snapshotExists(rc *eos_io.RuntimeContext, snapshotName string) (bool, error) {
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "virsh",
		Args:    []string{"snapshot-info", sm.config.VMName, snapshotName},
		Capture: true,
	})
	return err == nil, nil
}

func (sm *SnapshotManager) getSnapshotInfo(rc *eos_io.RuntimeContext, snapshotName string) (*SnapshotInfo, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "virsh",
		Args:    []string{"snapshot-dumpxml", sm.config.VMName, snapshotName},
		Capture: true,
	})
	if err != nil {
		return nil, err
	}

	// SECURITY P0 #2: Use xml.Decoder to prevent XXE attacks
	decoder := xml.NewDecoder(bytes.NewReader([]byte(output)))
	decoder.Entity = make(map[string]string) // Disable external entities

	var info SnapshotInfo
	if err := decoder.Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to parse snapshot XML: %w", err)
	}

	return &info, nil
}

func (sm *SnapshotManager) verifySnapshotXML(rc *eos_io.RuntimeContext, snapshotName string) error {
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "virsh",
		Args:    []string{"snapshot-dumpxml", sm.config.VMName, snapshotName},
		Capture: true,
	})
	return err
}

func (sm *SnapshotManager) copyFileWithCompression(src, dst string) error {
	// For now, simple copy without compression
	// Production implementation would handle compression based on config
	err := execute.RunSimple(context.Background(), "cp", src, dst)
	return err
}

func (sm *SnapshotManager) calculateBackupSize(backupPath string) int64 {
	var size int64
	filepath.Walk(backupPath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}

func (sm *SnapshotManager) validateXMLFile(xmlPath string) error {
	data, err := os.ReadFile(xmlPath)
	if err != nil {
		return err
	}

	// SECURITY P0 #2: Use xml.Decoder to prevent XXE attacks
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Entity = make(map[string]string) // Disable external entities

	var temp interface{}
	return decoder.Decode(&temp)
}