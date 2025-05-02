package docker

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// RemoveVolumes deletes the specified Docker volumes.
func RemoveVolumes(volumes []string, log *zap.Logger) error {
	for _, volume := range volumes {
		if err := execute.Execute("docker", "volume", "rm", volume); err != nil {
			log.Warn("Failed to remove volume", zap.String("volume", volume), zap.Error(err))
			return fmt.Errorf("failed to remove volume %s: %w", volume, err)
		}
	}
	return nil
}

// BackupVolume creates a tar.gz backup of a single Docker volume.
func BackupVolume(volumeName, backupDir string, log *zap.Logger) (string, error) {
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
	if err := execute.Execute("docker", cmd...); err != nil {
		return "", fmt.Errorf("failed to backup volume %s: %w", volumeName, err)
	}
	return filepath.Join(backupDir, backupFile), nil
}

// BackupVolumes backs up all provided Docker volumes to the backupDir.
func BackupVolumes(volumes []string, backupDir string, log *zap.Logger) (map[string]string, error) {
	backupResults := make(map[string]string)

	if err := os.MkdirAll(backupDir, shared.DirPermStandard); err != nil {
		return backupResults, fmt.Errorf("failed to create backup directory %s: %w", backupDir, err)
	}

	for _, vol := range volumes {
		backupFile, err := BackupVolume(vol, backupDir, log)
		if err != nil {
			log.Warn("Failed to backup volume", zap.String("volume", vol), zap.Error(err))
			continue // skip this volume, continue with others
		}
		backupResults[vol] = backupFile
	}
	return backupResults, nil
}
