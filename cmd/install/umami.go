package install

import (
	"fmt"
	"os"

	"eos/pkg/config"
	"eos/pkg/logger"
	"eos/pkg/utils"

	"go.uber.org/zap"
	"github.com/spf13/cobra"
)

// Declare a package-level Zap logger pointer:
var log *zap.Logger

// umamiCmd represents the Umami installation command.
var umamiCmd = &cobra.Command{
	Use:   "umami",
	Short: "Install and deploy Umami",
	Long: `Install and deploy Umami to /opt/umami, including installing 
dependencies, setting up the repository, and deploying with Docker Compose.`,
	Run: func(cmd *cobra.Command, args []string) {

		Log.Info("Starting Umami installation using Eos")

		// Ensure the installation directory exists
		if _, err := os.Stat(config.UmamiDir); os.IsNotExist(err) {
			Log.Warn("Installation directory does not exist; creating it",
				zap.String("path", config.UmamiDir))
			if err := os.MkdirAll(config.UmamiDir, 0755); err != nil {
				Log.Fatal("Failed to create installation directory", zap.Error(err))
			}
		} else {
			Log.Info("Installation directory exists",
				zap.String("path", config.UmamiDir))
		}

		// Install Yarn
		Log.Info("Installing Yarn")
		if err := utils.Execute("sudo", "npm", "install", "-g", "yarn"); err != nil {
			Log.Fatal("Error installing Yarn", zap.Error(err))
		}

		// Clone the Umami repository into the installation directory
		Log.Info("Cloning the Umami repository",
			zap.String("repo", "https://github.com/umami-software/umami.git"))
		if err := utils.Execute("git", "clone",
			"https://github.com/umami-software/umami.git", config.UmamiDir); err != nil {
			Log.Fatal("Error cloning Umami repository", zap.Error(err))
		}

		// Change directory to the cloned repository and run "yarn install"
		umamiRepoPath := fmt.Sprintf("%s/umami", config.UmamiDir)
		Log.Info("Running 'yarn install'",
			zap.String("directory", umamiRepoPath))
		if err := utils.ExecuteInDir(umamiRepoPath, "yarn", "install"); err != nil {
			Log.Fatal("Error running 'yarn install'", zap.Error(err))
		}

		// Display configuration instructions for .env file
		Log.Info("Configuration required: Create an .env file with DATABASE_URL")
		fmt.Println(`Create an .env file with the following content:
DATABASE_URL={connection url}

For example:
DATABASE_URL=postgresql://username:mypassword@localhost:5432/mydb`)

		// Deploy Umami with Docker Compose
		Log.Info("Deploying Umami with Docker Compose",
			zap.String("directory", config.UmamiDir))
		if err := utils.ExecuteInDir(config.UmamiDir, "docker", "compose", "up", "-d"); err != nil {
			Log.Fatal("Error running 'docker compose up -d'", zap.Error(err))
		}

		Log.Info("Umami installation and deployment complete!")
	},
}

func init() {
	// Assuming InstallCmd is declared in this same package (install.go, for instance).
	InstallCmd.AddCommand(umamiCmd)
}
