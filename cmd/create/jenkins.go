// cmd/create/jenkins.go

package create

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// jenkinsCmd represents the Jenkins installation command.
var CreateJenkinsCmd = &cobra.Command{
	Use:   "jenkins",
	Short: "Install and deploy Jenkins",
	Long: `Install and deploy Jenkins to /opt/jenkins by:
- Copying the Docker Compose file from eos/assets/jenkins-docker-compose.yml to /opt/jenkins
- Replacing all instances of "changeme" with a strong random alphanumeric password
- Running "docker compose up -d" to deploy
- Waiting 5 seconds and listing running containers via "docker ps"
- Informing the user to navigate to :8059 and log in with default credentials (admin/<generated_password>), and change the password immediately.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {

		zap.L().Info("Starting Jenkins installation using Eos")

		// Ensure the installation directory exists
		if _, err := os.Stat(shared.JenkinsDir); os.IsNotExist(err) {
			zap.L().Warn("Installation directory does not exist; creating it", zap.String("path", shared.JenkinsDir))
			if err := os.MkdirAll(shared.JenkinsDir, shared.DirPermStandard); err != nil {
				zap.L().Fatal("Failed to create installation directory", zap.Error(err))
			}
		} else {
			zap.L().Info("Installation directory exists", zap.String("path", shared.JenkinsDir))
		}

		// Prepare the Docker Compose file paths
		sourceComposeFile := "assets/jenkins-docker-compose.yml"
		destComposeFile := filepath.Join(shared.JenkinsDir, "jenkins-docker-compose.yml")

		zap.L().Info("Copying and processing Docker Compose file",
			zap.String("source", sourceComposeFile),
			zap.String("destination", destComposeFile))

		// Read the source Docker Compose file
		data, err := os.ReadFile(sourceComposeFile)
		if err != nil {
			zap.L().Fatal("Failed to read Docker Compose file from assets", zap.Error(err))
		}

		// Generate a strong random alphanumeric password (20 characters)
		zap.L().Info("Generating strong random password")
		password, err := crypto.GeneratePassword(20)
		if err != nil {
			zap.L().Fatal("Failed to generate password", zap.Error(err))
		}

		// Replace all occurrences of "changeme" with the generated password
		newData := strings.ReplaceAll(string(data), "changeme", password)
		zap.L().Info("Replaced 'changeme' with generated password", zap.String("password", password))

		// Write the processed Docker Compose file to the destination directory
		if err := os.WriteFile(destComposeFile, []byte(newData), 0644); err != nil {
			zap.L().Fatal("Failed to write processed Docker Compose file", zap.Error(err))
		}
		zap.L().Info("Docker Compose file processed and copied successfully")

		// Check if arachne-net docker network exists, creating it if not
		if err := docker.EnsureArachneNetwork(); err != nil {
			zap.L().Fatal("Error checking or creating 'arachne-net'", zap.Error(err))
		} else {
			zap.L().Info("Successfully ensured 'arachne-net' exists")
		}

		// Deploy Jenkins with Docker Compose using the processed file
		zap.L().Info("Deploying Jenkins with Docker Compose", zap.String("directory", shared.JenkinsDir))
		if err := execute.RunSimple(shared.JenkinsDir, "docker", "compose", "-f", destComposeFile, "up", "-d"); err != nil {
			zap.L().Fatal("Error running 'docker compose up -d'", zap.Error(err))
		}

		// Wait 5 seconds for the containers to start
		zap.L().Info("Waiting 5 seconds for containers to initialize...")
		time.Sleep(5 * time.Second)

		// Execute "docker ps" to list running containers
		if err := docker.CheckDockerContainers(); err != nil {
			zap.L().Fatal("Error checking running Docker containers", zap.Error(err))
		}

		// outputInitialAdminPassword retrieves the initial Jenkins admin password from the running container
		// and outputs it to the terminal with instructions for the user.
		outputInitialAdminPassword := func() {
			// Define the Jenkins container name as used in your docker-compose file.
			containerName := "jenkins"

			// Execute the command to retrieve the initial admin password from the container.
			cmd := exec.Command("docker", "exec", containerName, "cat", "/var/jenkins_home/secrets/initialAdminPassword")
			output, err := cmd.CombinedOutput()
			if err != nil {
				zap.L().Warn("Failed to retrieve initial admin password from container", zap.Error(err))
				fmt.Println("Warning: Could not retrieve the initial admin password. Please check the container logs for more details.")
				return
			}

			// Trim any whitespace from the output.
			password := strings.TrimSpace(string(output))
			zap.L().Info("Retrieved initial admin password", zap.String("password", password))

			// Print the instructions along with the password.
			fmt.Printf("\nUnlock Jenkins:\nTo unlock Jenkins, please copy the following administrator password and paste it into the Jenkins unlock prompt:\n\n%s\n\n", password)
		}

		// Call the inline function.
		outputInitialAdminPassword()

		// Final congratulatory message with instructions
		zap.L().Info("Jenkins installation complete",
			zap.String("message", fmt.Sprintf("Congratulations! Navigate to http://%s:8059 to access Jenkins. In line with best practice, change your password immediately.", system.GetInternalHostname())))

		return nil
	}),
}

func init() {

	CreateCmd.AddCommand(CreateJenkinsCmd)

}
