// cmd/delete/umami.go

package delete

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/types"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var DeleteUmamiCmd = &cobra.Command{
	Use:   "umami",
	Short: "Delete and clean up Umami",
	Long: `Stops and removes Umami containers, backs up the data volumes,
and deletes the installed images.
The backup is stored in /srv/container-volume-backups/{timestamp}_umami_db_data.tar.gz`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log.Info("Starting Umami deletion process using Eos")

		// Define the path to the docker-compose file used during installation.
		composePath := types.UmamiComposeYML

		// Parse the compose file to retrieve container names, images, and volumes.
		data, err := docker.ParseComposeFile(composePath)
		if err != nil {
			log.Fatal("Error parsing docker-compose file", zap.Error(err))
		}
		containers, images, volumes := docker.ExtractComposeMetadata(data)
		if err != nil {
			log.Fatal("Error parsing docker-compose file", zap.Error(err))
		}

		// Backup all volumes defined in the compose file.
		backupDir := "/srv/container-volume-backups"
		backupResults, err := docker.BackupVolumes(volumes, backupDir)
		if err != nil {
			log.Error("Error backing up volumes", zap.Error(err))
		} else {
			log.Info("All volumes backed up successfully", zap.Any("backups", backupResults))
		}

		// Stop all containers defined in the compose file.
		log.Info("Stopping containers defined in docker-compose", zap.Any("containers", containers))
		if err := docker.StopContainers(containers); err != nil {
			log.Error("Error stopping containers", zap.Error(err))
		} else {
			log.Info("Containers stopped successfully")
		}

		// Remove containers.
		log.Info("Removing containers defined in docker-compose", zap.Any("containers", containers))
		if err := docker.RemoveContainers(containers); err != nil {
			log.Error("Error removing containers", zap.Error(err))
		}

		// Remove images.
		log.Info("Removing images defined in docker-compose", zap.Any("images", images))
		if err := docker.RemoveImages(images); err != nil {
			log.Error("Error removing images", zap.Error(err))
		}

		// Now remove the volumes after backup
		log.Info("Removing volumes defined in docker-compose", zap.Any("volumes", volumes))
		if err := docker.RemoveVolumes(volumes); err != nil {
			log.Error("Error removing volumes", zap.Error(err))
		} else {
			log.Info("Volumes removed successfully")
		}

		log.Info("Umami deletion process complete")
		return nil
	}),
}

func init() {

	DeleteCmd.AddCommand(DeleteUmamiCmd)

}
