package storage

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ResizeFilesystem resizes a filesystem to use all available space
func ResizeFilesystem(rc *eos_io.RuntimeContext, devicePath, fsType, mountpoint string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting filesystem resize operation",
		zap.String("device", devicePath),
		zap.String("fs_type", fsType),
		zap.String("mountpoint", mountpoint))

	// ASSESS - Check if device exists and filesystem type
	if _, err := os.Stat(devicePath); os.IsNotExist(err) {
		return fmt.Errorf("device %s does not exist", devicePath)
	}

	// INTERVENE - Resize filesystem based on type
	switch fsType {
	case "ext4", "ext3", "ext2":
		// Use resize2fs for ext filesystems
		cmd := exec.Command("resize2fs", devicePath)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to resize ext filesystem: %w", err)
		}
	case "xfs":
		// Use xfs_growfs for XFS filesystems
		if mountpoint == "" {
			return fmt.Errorf("mountpoint required for XFS filesystem resize")
		}
		cmd := exec.Command("xfs_growfs", mountpoint)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to resize XFS filesystem: %w", err)
		}
	default:
		return fmt.Errorf("unsupported filesystem type: %s", fsType)
	}

	// EVALUATE - Check if resize was successful
	logger.Info("Filesystem resize completed successfully",
		zap.String("device", devicePath),
		zap.String("fs_type", fsType))

	return nil
}
