// cmd/delete/jenkins.go
package delete

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// deleteJenkinsCmd represents the command to delete Jenkins.
var DeleteJenkinsCmd = &cobra.Command{
	Use:   "jenkins",
	Short: "Delete and clean up Jenkins",
	Long: `Stops and removes Jenkins containers, backs up the data volumes,
and deletes the installed images.
The backup is stored in /srv/container-volume-backups/{timestamp}_jenkins_data.tar.gz`,
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		zap.L().Info("Starting Jenkins deletion process using Eos")

		// Define the path to the docker-compose file used during installation.
		composePath := shared.JenkinsComposeYML

		// Parse the compose file to retrieve container names, images, and volumes.
		data, err := container.ParseComposeFile(composePath)
		if err != nil {
			zap.L().Fatal("Error parsing docker-compose file", zap.Error(err))
		}
		containers, images, volumes := container.ExtractComposeMetadata(data)
		if err != nil {
			zap.L().Fatal("Error parsing docker-compose file", zap.Error(err))
		}

		// Backup all volumes defined in the compose file.
		backupDir := "/srv/container-volume-backups"
		backupResults, err := container.BackupVolumes(volumes, backupDir)
		if err != nil {
			zap.L().Error("Error backing up volumes", zap.Error(err))
		} else {
			zap.L().Info("All volumes backed up successfully", zap.Any("backups", backupResults))
		}

		// Stop all containers defined in the compose file.
		zap.L().Info("Stopping containers defined in docker-compose", zap.Any("containers", containers))
		if err := container.StopContainers(containers); err != nil {
			zap.L().Error("Error stopping containers", zap.Error(err))
		} else {
			zap.L().Info("Containers stopped successfully")
		}

		// Remove containers.
		zap.L().Info("Removing containers defined in docker-compose", zap.Any("containers", containers))
		if err := container.RemoveContainers(containers); err != nil {
			zap.L().Error("Error removing containers", zap.Error(err))
		}

		// Remove images.
		zap.L().Info("Removing images defined in docker-compose", zap.Any("images", images))
		if err := container.RemoveImages(images); err != nil {
			zap.L().Error("Error removing images", zap.Error(err))
		}

		// Now remove the volumes after backup.
		zap.L().Info("Removing volumes defined in docker-compose", zap.Any("volumes", volumes))
		if err := container.RemoveVolumes(volumes); err != nil {
			zap.L().Error("Error removing volumes", zap.Error(err))
		} else {
			zap.L().Info("Volumes removed successfully")
		}

		zap.L().Info("Jenkins deletion process complete")
		return nil
	}),
}

func init() {

	DeleteCmd.AddCommand(DeleteJenkinsCmd)

}
