/* cmd/hecate/backup/config.go */

package backup

import (
	"context"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// backupCmd represents the backup command.
var BackupConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Backup configuration and files",
	Long:  `Backup important configuration directories and files.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		stdCtx := context.Background() // 🛠️ new: get context safely

		// Backup the conf.d directory.
		srcInfo, err := os.Stat(hecate.ConfDir)

		if info, err := os.Stat(hecate.ConfDir); err != nil || !info.IsDir() {
			zap.L().Error("Missing or invalid conf.d", zap.String("dir", hecate.ConfDir), zap.Error(err))
			os.Exit(1)
		}

		if err != nil || !srcInfo.IsDir() {
			zap.L().Error("Error: Source directory '%s' does not exist.\n")
			os.Exit(1)
		}
		if err := system.Rm(stdCtx, hecate.BackupConf, "backup conf"); err != nil {
			zap.L().Error("Failed to remove existing backup", zap.String("path", hecate.BackupConf), zap.Error(err))
			os.Exit(1)
		}
		if err := system.CopyDir(hecate.ConfDir, hecate.BackupConf); err != nil {
			zap.L().Error("Backup failed", zap.String("src", shared.DefaultConfDir), zap.Error(err))
			os.Exit(1)
		}
		zap.L().Info("Backup complete: '%s' has been backed up to '%s'.\n")

		// Backup the certs directory.
		srcInfo, err = os.Stat(hecate.DstCerts)
		if err != nil || !srcInfo.IsDir() {
			zap.L().Error("Missing or invalid certs", zap.String("dir", shared.DefaultCertsDir), zap.Error(err))
			os.Exit(1)
		}
		if err := system.Rm(stdCtx, hecate.BackupConf, "backup conf"); err != nil {
			zap.L().Error("Failed to remove existing hecate.Backup", zap.String("path", hecate.BackupCerts), zap.Error(err))
			os.Exit(1)
		}
		if err := system.CopyDir(hecate.DstCerts, hecate.BackupCerts); err != nil {
			zap.L().Error("Backup failed", zap.String("src", shared.DefaultCertsDir), zap.Error(err))
			os.Exit(1)
		}
		zap.L().Info("Backup complete: '%s' has been backed up to '%s'.\n")

		// Backup the docker-compose.yml file.
		srcInfo, err = os.Stat(hecate.DockerComposeFile)
		if err != nil || srcInfo.IsDir() {
			zap.L().Error("Missing or invalid compose file", zap.String("file", shared.DefaultComposeYML), zap.Error(err))
			os.Exit(1)
		}
		if err := system.Rm(stdCtx, hecate.BackupConf, "backup conf"); err != nil {
			zap.L().Error("Failed to remove existing backup", zap.String("path", hecate.BackupCompose), zap.Error(err))
			os.Exit(1)
		}
		if err := system.CopyFile(hecate.DockerComposeFile, hecate.BackupCompose, 0); err != nil {
			zap.L().Error("Backup failed", zap.String("src", shared.DefaultComposeYML), zap.Error(err))
			os.Exit(1)
		}
		zap.L().Info("✅ docker-compose.yml backed up", zap.String("dest", hecate.BackupCompose))
		zap.L().Info("🎉 All backup tasks completed successfully", zap.String("timestamp", hecate.Timestamp))
		return nil

	}),
}

func init() {
	BackupCmd.AddCommand(BackupConfigCmd)
}
