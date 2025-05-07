package backup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func init() {
	BackupCmd.AddCommand(BackupHecateCmd)
}

// BackupHecateCmd defines the CLI command for backing up /opt/hecate.
var BackupHecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Back up the /opt/hecate directory into /opt/mnt with a timestamped archive",
	RunE: func(cmd *cobra.Command, args []string) error {
		log := zap.L().Named("backup-hecate")

		// Define source and destination
		sourceDir := "/opt/hecate"
		destDir := "/opt/mnt"

		// Ensure /opt/hecate exists
		if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
			log.Error("Source directory does not exist", zap.String("path", sourceDir))
			return fmt.Errorf("source directory %s does not exist", sourceDir)
		}

		// Ensure /opt/mnt exists, create if not
		if _, err := os.Stat(destDir); os.IsNotExist(err) {
			log.Info("Destination directory does not exist, creating...", zap.String("path", destDir))
			if err := os.MkdirAll(destDir, 0755); err != nil {
				log.Error("Failed to create destination directory", zap.Error(err))
				return fmt.Errorf("failed to create %s: %w", destDir, err)
			}
			log.Info("✅ Destination directory created", zap.String("path", destDir))
		}

		// Prepare timestamped backup filename
		timestamp := time.Now().Format("20060102_150405")
		backupFileName := fmt.Sprintf("%s_hecate_backup.tar.gz", timestamp)
		backupFilePath := filepath.Join(destDir, backupFileName)

		log.Info("Starting backup...",
			zap.String("source", sourceDir),
			zap.String("destination", backupFilePath),
		)

		// Use tar to create a compressed archive
		cmdTar := exec.Command(
			"tar",
			"-czvf", backupFilePath,
			"-C", "/opt", "hecate",
		)

		output, err := cmdTar.CombinedOutput()
		log.Info("tar output", zap.ByteString("output", output))

		if err != nil {
			log.Error("Failed to create backup archive", zap.Error(err))
			return fmt.Errorf("failed to create backup archive: %w", err)
		}

		log.Info("✅ Backup completed successfully", zap.String("backup_file", backupFilePath))
		return nil
	},
}
