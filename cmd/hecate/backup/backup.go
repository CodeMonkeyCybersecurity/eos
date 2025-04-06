// cmd/backup/backup.go

/*
Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

*/

package backup

import (
	"os"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consts"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

var log = logger.L()

// backupCmd represents the backup command.
var BackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup configuration and files",
	Long:  `Backup important configuration directories and files.`,
	Run: func(cmd *cobra.Command, args []string) {
		runBackup()
	},
}

// runBackup is called when the user runs "hecate create backup".
func runBackup() {
	timestamp := time.Now().Format("20060102-150405")
	backupConf := consts.DefaultConfDir + "." + timestamp + ".bak"
	backupCerts := consts.DefaultCertsDir + "." + timestamp + ".bak"
	backupCompose := consts.DefaultComposeYML + "." + timestamp + ".bak"

	// conf.d
	if info, err := os.Stat(consts.DefaultConfDir); err != nil || !info.IsDir() {
		log.Error("Missing or invalid conf.d", zap.String("dir", consts.DefaultConfDir), zap.Error(err))
		os.Exit(1)
	}
	if err := utils.RemoveIfExists(backupConf); err != nil {
		log.Error("Failed to remove existing backup", zap.String("path", backupConf), zap.Error(err))
		os.Exit(1)
	}

	if err := utils.CopyDir(consts.DefaultConfDir, backupConf); err != nil {
		log.Error("Backup failed", zap.String("src", consts.DefaultConfDir), zap.Error(err))
		os.Exit(1)
	}
	log.Info("✅ conf.d backed up", zap.String("dest", backupConf))

	// certs
	if info, err := os.Stat(consts.DefaultCertsDir); err != nil || !info.IsDir() {
		log.Error("Missing or invalid certs", zap.String("dir", consts.DefaultCertsDir), zap.Error(err))
		os.Exit(1)
	}
	if err := utils.RemoveIfExists(backupCerts); err != nil {
		log.Error("Failed to remove existing backup", zap.String("path", backupCerts), zap.Error(err))
		os.Exit(1)
	}
	if err := utils.CopyDir(consts.DefaultCertsDir, backupCerts); err != nil {
		log.Error("Backup failed", zap.String("src", consts.DefaultCertsDir), zap.Error(err))
		os.Exit(1)
	}
	log.Info("✅ certs backed up", zap.String("dest", backupCerts))

	// docker-compose.yml
	if info, err := os.Stat(consts.DefaultComposeYML); err != nil || info.IsDir() {
		log.Error("Missing or invalid compose file", zap.String("file", consts.DefaultComposeYML), zap.Error(err))
		os.Exit(1)
	}
	if err := utils.RemoveIfExists(backupCompose); err != nil {
		log.Error("Failed to remove existing backup", zap.String("path", backupCompose), zap.Error(err))
		os.Exit(1)
	}
	if err := utils.CopyFile(consts.DefaultComposeYML, backupCompose); err != nil {
		log.Error("Backup failed", zap.String("src", consts.DefaultComposeYML), zap.Error(err))
		os.Exit(1)
	}
	log.Info("✅ docker-compose.yml backed up", zap.String("dest", backupCompose))
	log.Info("🎉 All backup tasks completed successfully", zap.String("timestamp", timestamp))
}
