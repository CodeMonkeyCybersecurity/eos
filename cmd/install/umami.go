package cmd

import (
	"fmt"
	"go.uber.org/zap"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)


var logger *zap.Logger

// umamiCmd represents the Umami installation command.
var umamiCmd = &cobra.Command{
	Use:   "umami",
	Short: "Install and deploy Umami",
	Long:  "Install and deploy Umami to /opt/umami, including installing dependencies, setting up the repository, and deploying with Docker Compose.",
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize Zap logger
		logger, _ = zap.NewProduction()
		defer logger.Sync()

		logger.Info("Starting Umami installation using Eos")

		// Ensure the installation directory exists
		if _, err := os.Stat(umamiDir); os.IsNotExist(err) {
			logger.Warn("Installation directory does not exist, creating it", zap.String("path", umamiDir))
			if err := os.MkdirAll(umamiDir, 0755); err != nil {
				logger.Fatal("Failed to create installation directory", zap.Error(err))
			}
		} else {
			logger.Info("Installation directory exists", zap.String("path", umamiDir))
		}

		// Install Yarn
		logger.Info("Installing Yarn")
		if err := utils.Execute("sudo", "npm", "install", "-g", "yarn"); err != nil {
			logger.Fatal("Error installing Yarn", zap.Error(err))
		}

		// Clone the Umami repository into the installation directory
		logger.Info("Cloning the Umami repository", zap.String("repo", "https://github.com/umami-software/umami.git"))
		if err := utils.Execute("git", "clone", "https://github.com/umami-software/umami.git", umamiDir); err != nil {
			logger.Fatal("Error cloning Umami repository", zap.Error(err))
		}

		// Change directory to the cloned repository and run "yarn install"
		umamiRepoPath := fmt.Sprintf("%s/umami", umamiDir)
		logger.Info("Running 'yarn install'", zap.String("directory", umamiRepoPath))
		if err := utils.ExecuteInDir(umamiRepoPath, "yarn", "install"); err != nil {
			logger.Fatal("Error running 'yarn install'", zap.Error(err))
		}

		// Display configuration instructions for .env file
		logger.Info("Configuration required: Create an .env file with DATABASE_URL")
		fmt.Println(`Create an .env file with the following content:
DATABASE_URL={connection url}

For example:
DATABASE_URL=postgresql://username:mypassword@localhost:5432/mydb`)

		// Deploy Umami with Docker Compose
		logger.Info("Deploying Umami with Docker Compose", zap.String("directory", umamiDir))
		if err := utils.ExecuteInDir(umamiDir, "docker", "compose", "up", "-d"); err != nil {
			logger.Fatal("Error running 'docker compose up -d'", zap.Error(err))
		}

		logger.Info("Umami installation and deployment complete!")
	},
}

func init() {
	// Assuming you have an 'install' command group, add the umami command as a subcommand.
	installCmd.AddCommand(umamiCmd)
}
