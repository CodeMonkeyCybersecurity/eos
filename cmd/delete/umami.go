// cmd/delete/umami.go
package delete

import (
	"fmt"
	"os"
	"time"

	"eos/pkg/config"
	"eos/pkg/utils"

	"go.uber.org/zap"
	"github.com/spf13/cobra"
)

// umamiDeleteCmd represents the command to delete Umami.
var umamiDeleteCmd = &cobra.Command{
	Use:   "umami",
	Short: "Delete and clean up Umami",
	Long: `Stops and removes Umami containers, backs up the data volumes,
and deletes the installed images.
The backup is stored in /srv/container-volume-backups/{timestamp}_umami_db_data.tar.gz`,
	Run: func(cmd *cobra.Command, args []string) {

		log := utils.GetLogger()
		log.Info("Starting Umami deletion process using Eos")

		// Stop containers (umami and umami-db)
		log.Info("Stopping Umami containers")
		if err := utils.Execute("docker", "stop", "umami", "umami-db"); err != nil {
			log.Error("Error stopping containers", zap.Error(err))
		} else {
			log.Info("Containers stopped successfully")
		}

		// Backup volumes: assuming the data volume is named "umami_db_data"
		backupDir := "/srv/container-volume-backups"
		// Ensure the backup directory exists
		if err := os.MkdirAll(backupDir, 0755); err != nil {
			log.Fatal("Failed to create backup directory", zap.Error(err))
		}

		timestamp := time.Now().Format("20060102_150405")
		backupFile := fmt.Sprintf("%s/%s_umami_db_data.tar.gz", backupDir, timestamp)
		log.Info("Backing up volume 'umami_db_data'", zap.String("backupFile", backupFile))

		// Run a temporary container to backup the volume using alpine and tar
		backupCmd := []string{
			"docker", "run", "--rm",
			"-v", "umami_db_data:/volume",
			"-v", fmt.Sprintf("%s:/backup", backupDir),
			"alpine",
			"tar", "czf", fmt.Sprintf("/backup/%s_umami_db_data.tar.gz", timestamp),
			"-C", "/volume", ".",
		}
		if err := utils.Execute(backupCmd[0], backupCmd[1:]...); err != nil {
			log.Fatal("Error backing up volume", zap.Error(err))
		} else {
			log.Info("Volume backup completed successfully")
		}

		// Remove containers
		log.Info("Removing Umami containers")
		if err := utils.Execute("docker", "rm", "umami", "umami-db"); err != nil {
			log.Error("Error removing containers", zap.Error(err))
		} else {
			log.Info("Containers removed successfully")
		}

		// Delete installed images
		log.Info("Removing Umami images")
		// Remove the Umami image
		if err := utils.Execute("docker", "rmi", "ghcr.io/umami-software/umami:postgresql-latest"); err != nil {
			log.Error("Error removing Umami image", zap.Error(err))
		} else {
			log.Info("Umami image removed successfully")
		}
		// Remove the Postgres image used by Umami
		if err := utils.Execute("docker", "rmi", "postgres:15-alpine"); err != nil {
			log.Error("Error removing Postgres image", zap.Error(err))
		} else {
			log.Info("Postgres image removed successfully")
		}

		log.Info("Umami deletion process complete. Data backup is available at", zap.String("backupFile", backupFile))
	},
}
