package backup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BackupHecateCmd defines the CLI command for backing up /opt/hecate.
var BackupHecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Back up the /opt/hecate directory into /opt/mnt with a timestamped archive",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		exportTarget, _ := cmd.Flags().GetString("export")
		outputDir, _ := cmd.Flags().GetString("output-dir")

		// Ensure output directory exists before performing any operations.
		if outputDir == "" {
			outputDir = "/opt/mnt"
		}
		if err := os.MkdirAll(outputDir, 0o755); err != nil {
			log.Error("Failed to create destination directory", zap.Error(err))
			return fmt.Errorf("failed to create %s: %w", outputDir, err)
		}

		if exportTarget != "" {
			switch exportTarget {
			case "authentik-blueprint":
				log.Info("Exporting Authentik blueprint",
					zap.String("destination_dir", outputDir))

				blueprintPath, err := authentik.ExportBlueprintToDirectory(rc, outputDir)
				if err != nil {
					log.Error("Failed to export Authentik blueprint", zap.Error(err))
					return err
				}

				log.Info("Authentik blueprint export completed",
					zap.String("blueprint_path", blueprintPath))
				return nil
			default:
				return fmt.Errorf("unsupported export target: %s", exportTarget)
			}
		}

		// Define source and destination
		sourceDir := "/opt/hecate"

		// Ensure /opt/hecate exists
		if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
			log.Error("Source directory does not exist", zap.String("path", sourceDir))
			return fmt.Errorf("source directory %s does not exist", sourceDir)
		}

		// Prepare timestamped backup filename
		timestamp := time.Now().Format("20060102_150405")
		backupFileName := fmt.Sprintf("%s_hecate_backup.tar.gz", timestamp)
		backupFilePath := filepath.Join(outputDir, backupFileName)

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

		log.Info(" Backup completed successfully", zap.String("backup_file", backupFilePath))
		return nil
	}),
}

func init() {
	BackupHecateCmd.Flags().String("export", "", "Export supplemental data instead of creating archive (options: authentik-blueprint)")
	BackupHecateCmd.Flags().String("output-dir", "/opt/mnt", "Destination directory for backups or exports")
	BackupCmd.AddCommand(BackupHecateCmd)
}
