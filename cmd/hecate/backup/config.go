/* cmd/hecate/backup/config.go */

package backup

import (
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/types"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// backupCmd represents the backup command.
var BackupConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Backup configuration and files",
	Long:  `Backup important configuration directories and files.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Backup the conf.d directory.
		srcInfo, err := os.Stat(hecate.ConfDir)

		if info, err := os.Stat(hecate.ConfDir); err != nil || !info.IsDir() {
			log.Error("Missing or invalid conf.d", zap.String("dir", hecate.ConfDir), zap.Error(err))
			os.Exit(1)
		}

		if err != nil || !srcInfo.IsDir() {
			log.Error("Error: Source directory '%s' does not exist.\n")
			os.Exit(1)
		}
		if err := system.Rm(hecate.BackupConf, "backup conf", log); err != nil {
			log.Error("Failed to remove existing backup", zap.String("path", hecate.BackupConf), zap.Error(err))
			os.Exit(1)
		}
		if err := system.CopyDir(hecate.ConfDir, hecate.BackupConf, log); err != nil {
			log.Error("Backup failed", zap.String("src", types.DefaultConfDir), zap.Error(err))
			os.Exit(1)
		}
		log.Info("Backup complete: '%s' has been backed up to '%s'.\n")

		// Backup the certs directory.
		srcInfo, err = os.Stat(hecate.DstCerts)
		if err != nil || !srcInfo.IsDir() {
			log.Error("Missing or invalid certs", zap.String("dir", types.DefaultCertsDir), zap.Error(err))
			os.Exit(1)
		}
		if err := system.Rm(hecate.BackupConf, "backup conf", log); err != nil {
			log.Error("Failed to remove existing hecate.Backup", zap.String("path", hecate.BackupCerts), zap.Error(err))
			os.Exit(1)
		}
		if err := system.CopyDir(hecate.DstCerts, hecate.BackupCerts, log); err != nil {
			log.Error("Backup failed", zap.String("src", types.DefaultCertsDir), zap.Error(err))
			os.Exit(1)
		}
		log.Info("Backup complete: '%s' has been backed up to '%s'.\n")

		// Backup the docker-compose.yml file.
		srcInfo, err = os.Stat(hecate.DockerComposeFile)
		if err != nil || srcInfo.IsDir() {
			log.Error("Missing or invalid compose file", zap.String("file", types.DefaultComposeYML), zap.Error(err))
			os.Exit(1)
		}
		if err := system.Rm(hecate.BackupConf, "backup conf", log); err != nil {
			log.Error("Failed to remove existing backup", zap.String("path", hecate.BackupCompose), zap.Error(err))
			os.Exit(1)
		}
		if err := system.CopyFile(hecate.DockerComposeFile, hecate.BackupCompose, 0, log); err != nil {
			log.Error("Backup failed", zap.String("src", types.DefaultComposeYML), zap.Error(err))
			os.Exit(1)
		}
		log.Info("✅ docker-compose.yml backed up", zap.String("dest", hecate.BackupCompose))
		log.Info("🎉 All backup tasks completed successfully", zap.String("timestamp", hecate.Timestamp))
		return nil

	}),
}

func init() {
	BackupCmd.AddCommand(BackupConfigCmd)
}
