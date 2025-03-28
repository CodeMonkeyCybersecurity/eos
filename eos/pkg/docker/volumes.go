// pkg/docker/volumes.go

package docker

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"

	"go.uber.org/zap"
)

// RemoveVolumes removes the specified Docker volumes.
func RemoveVolumes(volumes []string) error {
	for _, volume := range volumes {
		// Execute the docker volume rm command.
		if err := execute.Execute("docker", "volume", "rm", volume); err != nil {
			log.Warn("failed to remove volume", zap.String("volume", volume), zap.Error(err))
		} else {
			log.Info("Volume removed successfully", zap.String("volume", volume))
		}
	}
	return nil
}

// It returns the full path to the backup file.
func BackupVolume(volumeName, backupDir string) (string, error) {
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

// BackupVolumes backs up all provided volumes to the specified backupDir.
func BackupVolumes(volumes []string, backupDir string) (map[string]string, error) {
	backupResults := make(map[string]string)

	// Ensure the backup directory exists.
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return backupResults, fmt.Errorf("failed to create backup directory %s: %w", backupDir, err)
	}

	for _, vol := range volumes {
		log.Info("Backing up volume", zap.String("volume", vol))
		backupFile, err := BackupVolume(vol, backupDir)
		if err != nil {
			log.Error("Error backing up volume", zap.String("volume", vol), zap.Error(err))
		} else {
			log.Info("Volume backup completed", zap.String("volume", vol), zap.String("backupFile", backupFile))
			backupResults[vol] = backupFile
		}
	}
	return backupResults, nil
}
