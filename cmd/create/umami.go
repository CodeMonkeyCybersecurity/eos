// cmd/create/umami.go
package create

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// umamiCmd represents the Umami installation command.
var CreateUmamiCmd = &cobra.Command{
	Use:   "umami",
	Short: "Install and deploy Umami",
	Long: `Install and deploy Umami to /opt/umami by:
- Copying the Docker Compose file from eos/assets/umami-docker-compose.yml to /opt/umami
- Replacing all instances of "changeme" with a strong random alphanumeric password
- Running "docker compose up -d" to deploy
- Waiting 5 seconds and listing running containers via "docker ps"
- Informing the user to navigate to :8117 and log in with default credentials (admin/umami) and change the password immediately.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {

		log.Info("Starting Umami installation using Eos")

		// Ensure the installation directory exists
		if _, err := os.Stat(shared.UmamiDir); os.IsNotExist(err) {
			log.Warn("Installation directory does not exist; creating it",
				zap.String("path", shared.UmamiDir))
			if err := os.MkdirAll(shared.UmamiDir, shared.DirPermStandard); err != nil {
				log.Fatal("Failed to create installation directory", zap.Error(err))
			}
		} else {
			log.Info("Installation directory exists",
				zap.String("path", shared.UmamiDir))
		}

		// Prepare the Docker Compose file paths
		sourceComposeFile := "assets/umami-docker-compose.yml"
		destComposeFile := filepath.Join(shared.UmamiDir, "umami-docker-compose.yml")

		log.Info("Copying and processing Docker Compose file",
			zap.String("source", sourceComposeFile),
			zap.String("destination", destComposeFile))

		// Read the source Docker Compose file
		data, err := os.ReadFile(sourceComposeFile)
		if err != nil {
			log.Fatal("Failed to read Docker Compose file from assets", zap.Error(err))
		}

		// Generate a strong random alphanumeric password (20 characters)
		log.Info("Generating strong random password")
		password, err := crypto.GeneratePassword(20)
		if err != nil {
			log.Fatal("Failed to generate password", zap.Error(err))
		}

		// Replace all occurrences of "changeme" with the generated password
		newData := strings.ReplaceAll(string(data), "changeme", password)
		log.Info("Replaced 'changeme' with a generated password")

		// Write the processed Docker Compose file to the destination directory
		if err := os.WriteFile(destComposeFile, []byte(newData), 0644); err != nil {
			log.Fatal("Failed to write processed Docker Compose file", zap.Error(err))
		}
		log.Info("Docker Compose file processed and copied successfully")

		// Check if arache-net docker network already exists, create if not
		// Check if arachne-net docker network exists, creating it if not
		if err := docker.EnsureArachneNetwork(); err != nil {
			log.Fatal("Error checking or creating 'arachne-net'", zap.Error(err))
		} else {
			log.Info("Successfully ensured 'arachne-net' exists")
		}

		// Deploy Umami with Docker Compose using the processed file
		log.Info("Deploying Umami with Docker Compose",
			zap.String("directory", shared.UmamiDir))
		if err := execute.ExecuteInDir(shared.UmamiDir, "docker", "compose", "-f", destComposeFile, "up", "-d"); err != nil {
			log.Fatal("Error running 'docker compose up -d'", zap.Error(err))
		}

		// Wait 5 seconds for the containers to start
		log.Info("Waiting 5 seconds for containers to initialize...")
		time.Sleep(5 * time.Second)

		// Execute "docker ps" to list running containers
		if err := docker.CheckDockerContainers(); err != nil {
			log.Fatal("Error checking running Docker containers", zap.Error(err))
		}

		// Final congratulatory message with instructions
		log.Info("Umami installation complete",
			zap.String("message", fmt.Sprintf("Congratulations! Navigate to http://%s:8117 to access Umami. Login with username 'admin' and password 'umami'. Change your password immediately.", system.GetInternalHostname())))
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateUmamiCmd)

}
