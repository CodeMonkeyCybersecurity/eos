package install

import (
	"fmt"
	"os"

	"eos/pkg/utils"
	"eos/pkg/logger"
	"eos/pkg/config"

	"go.uber.org/zap"
	"github.com/spf13/cobra"
)


// Create a package-level variable 'log' pointing to your global logger:
var log *zap.Logger

func init() {
    log = logger.GetLogger()
}

// umamiCmd represents the Umami installation command.
var umamiCmd = &cobra.Command{
	Use:   "umami",
	Short: "Install and deploy Umami",
	Long:  "Install and deploy Umami to /opt/umami, including installing dependencies, setting up the repository, and deploying with Docker Compose.",
	Run: func(cmd *cobra.Command, args []string) {

		log.Info("Starting Umami installation using Eos")

		// Ensure the installation directory exists
		if _, err := os.Stat(config.UmamiDir); os.IsNotExist(err) {
			log.Warn("Installation directory does not exist, creating it", zap.String("path", config.UmamiDir))
			if err := os.MkdirAll(config.UmamiDir, 0755); err != nil {
				log.Fatal("Failed to create installation directory", zap.Error(err))
			}
		} else {
			log.Info("Installation directory exists", zap.String("path", config.UmamiDir))
		}

		// Install Yarn
		log.Info("Installing Yarn")
		if err := utils.Execute("sudo", "npm", "install", "-g", "yarn"); err != nil {
			log.Fatal("Error installing Yarn", zap.Error(err))
		}

		// Clone the Umami repository into the installation directory
		log.Info("Cloning the Umami repository", zap.String("repo", "https://github.com/umami-software/umami.git"))
		if err := utils.Execute("git", "clone", "https://github.com/umami-software/umami.git", config.UmamiDir); err != nil {
			log.Fatal("Error cloning Umami repository", zap.Error(err))
		}

		// Change directory to the cloned repository and run "yarn install"
		umamiRepoPath := fmt.Sprintf("%s/umami", config.UmamiDir)
		log.Info("Running 'yarn install'", zap.String("directory", umamiRepoPath))
		if err := utils.ExecuteInDir(umamiRepoPath, "yarn", "install"); err != nil {
			log.Fatal("Error running 'yarn install'", zap.Error(err))
		}

		// Display configuration instructions for .env file
		log.Info("Configuration required: Create an .env file with DATABASE_URL")
		fmt.Println(`Create an .env file with the following content:
DATABASE_URL={connection url}

For example:
DATABASE_URL=postgresql://username:mypassword@localhost:5432/mydb`)

		// Deploy Umami with Docker Compose
		log.Info("Deploying Umami with Docker Compose", zap.String("directory", config.UmamiDir))
		if err := utils.ExecuteInDir(config.UmamiDir, "docker", "compose", "up", "-d"); err != nil {
			log.Fatal("Error running 'docker compose up -d'", zap.Error(err))
		}

		log.Info("Umami installation and deployment complete!")
	},
}

func init() {
	// Assuming you have an 'install' command group, add the umami command as a subcommand.
	InstallCmd.AddCommand(umamiCmd)
}
