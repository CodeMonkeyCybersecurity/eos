package disk

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BackupManager handles VM disk backups
type BackupManager struct{}

// Create creates a backup of a VM disk
func (bm *BackupManager) Create(ctx context.Context, vmName, diskPath string) (string, error) {
	logger := otelzap.Ctx(ctx)

	// Ensure backup directory exists
	backupDir := "/var/lib/eos/backups/kvm"
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Generate backup filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	backupFilename := fmt.Sprintf("%s-pre-resize-%s.qcow2", vmName, timestamp)
	backupPath := filepath.Join(backupDir, backupFilename)

	logger.Info("Creating disk backup",
		zap.String("source", diskPath),
		zap.String("destination", backupPath))

	// Use qemu-img convert for backup (creates compressed copy)
	cmd := exec.CommandContext(ctx, "qemu-img", "convert",
		"-O", "qcow2",
		"-c", // Compress
		diskPath,
		backupPath,
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("backup failed: %w\nOutput: %s", err, output)
	}

	// Verify backup was created
	if _, err := os.Stat(backupPath); err != nil {
		return "", fmt.Errorf("backup file not found after creation: %w", err)
	}

	logger.Info("Backup created successfully",
		zap.String("path", backupPath))

	return backupPath, nil
}

// CreateSnapshot creates a libvirt snapshot (faster but requires more disk space)
func (bm *BackupManager) CreateSnapshot(ctx context.Context, vmName string) (string, error) {
	logger := otelzap.Ctx(ctx)

	snapshotName := fmt.Sprintf("pre-resize-%d", time.Now().Unix())

	logger.Info("Creating VM snapshot",
		zap.String("vm", vmName),
		zap.String("snapshot", snapshotName))

	// Use virsh snapshot-create-as (simpler than XML)
	cmd := exec.CommandContext(ctx, "virsh", "snapshot-create-as",
		vmName,
		snapshotName,
		"--description", "Pre-resize safety snapshot")

	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("snapshot creation failed: %w\nOutput: %s", err, output)
	}

	logger.Info("Snapshot created", zap.String("name", snapshotName))
	return snapshotName, nil
}
