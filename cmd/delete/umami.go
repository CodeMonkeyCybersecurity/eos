// cmd/delete/umami.go
package delete

import (
	"eos/pkg/config"
	"eos/pkg/utils"

	"go.uber.org/zap"
	"github.com/spf13/cobra"
)

// umamiDeleteCmd represents the command to delete Umami.
var deleteUmamiCmd = &cobra.Command{
	Use:   "umami",
	Short: "Delete and clean up Umami",
	Long: `Stops and removes Umami containers, backs up the data volumes,
and deletes the installed images.
The backup is stored in /srv/container-volume-backups/{timestamp}_umami_db_data.tar.gz`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("Starting Umami deletion process using Eos")

		// Define the path to the docker-compose file used during installation.
		composePath := config.UmamiDir + "/umami-docker-compose.yml"

		// Parse the compose file to retrieve container names, images, and volumes.
		containers, images, volumes, err := utils.ParseComposeFile(composePath)
		if err != nil {
			log.Fatal("Error parsing docker-compose file", zap.Error(err))
		}

		// Backup all volumes defined in the compose file.
		backupDir := "/srv/container-volume-backups"
		backupResults, err := utils.BackupVolumes(volumes, backupDir)
		if err != nil {
			log.Error("Error backing up volumes", zap.Error(err))
		} else {
			log.Info("All volumes backed up successfully", zap.Any("backups", backupResults))
		}
		
		// Stop all containers defined in the compose file.
		log.Info("Stopping containers defined in docker-compose", zap.Any("containers", containers))
		if err := utils.StopContainers(containers); err != nil {
		    log.Error("Error stopping containers", zap.Error(err))
		} else {
		    log.Info("Containers stopped successfully")
		}

		// Remove containers.
		log.Info("Removing containers defined in docker-compose", zap.Any("containers", containers))
		if err := utils.RemoveContainers(containers); err != nil {
			log.Error("Error removing containers", zap.Error(err))
		}

		// Remove images.
		log.Info("Removing images defined in docker-compose", zap.Any("images", images))
		if err := utils.RemoveImages(images); err != nil {
			log.Error("Error removing images", zap.Error(err))
		}

		// Now remove the volumes after backup
		log.Info("Removing volumes defined in docker-compose", zap.Any("volumes", volumes))
		if err := utils.RemoveVolumes(volumes); err != nil {
		    log.Error("Error removing volumes", zap.Error(err))
		} else {
		    log.Info("Volumes removed successfully")
		}
		
		log.Info("Umami deletion process complete")
	},
}
