// pkg/docker/volumes.go

package container

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RemoveVolumes deletes the specified Docker volumes.
func RemoveVolumes(rc *eos_io.RuntimeContext, volumes []string) error {
	for _, volume := range volumes {
		if err := execute.RunSimple(rc.Ctx, "docker", "volume", "rm", volume); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to remove volume", zap.String("volume", volume), zap.Error(err))
			return fmt.Errorf("failed to remove volume %s: %w", volume, err)
		}
	}
	return nil
}

// BackupVolume creates a tar.gz backup of a single Docker volume.
func BackupVolume(rc *eos_io.RuntimeContext, volumeName, backupDir string) (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	backupFile := fmt.Sprintf("%s_%s.tar.gz", timestamp, volumeName)
	cmd := []string{
		"run", "--rm",
		"-v", fmt.Sprintf("%s:/volume", volumeName),
		"-v", fmt.Sprintf("%s:/backup", backupDir),
		"alpine",
		"tar", "czf", fmt.Sprintf("/backup/%s", backupFile),
		"-C", "/volume", ".",
	}
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    cmd,
	})
	if err != nil {
		return "", fmt.Errorf("failed to backup volume %s: %w", volumeName, err)
	}
	return filepath.Join(backupDir, backupFile), nil
}

// BackupVolumes backs up all provided Docker volumes to the backupDir.
func BackupVolumes(rc *eos_io.RuntimeContext, volumes []string, backupDir string) (map[string]string, error) {
	backupResults := make(map[string]string)

	if err := os.MkdirAll(backupDir, shared.DirPermStandard); err != nil {
		return backupResults, fmt.Errorf("failed to create backup directory %s: %w", backupDir, err)
	}

	for _, vol := range volumes {
		backupFile, err := BackupVolume(rc, vol, backupDir)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to backup volume", zap.String("volume", vol), zap.Error(err))
			continue
		}
		backupResults[vol] = backupFile
	}
	return backupResults, nil
}
