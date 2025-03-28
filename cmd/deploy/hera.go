// cmd/deploy/hera.go

package deploy

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"eos/pkg/docker"
	"eos/pkg/logger"
	"eos/pkg/utils"
)

var deployHeraCmd = &cobra.Command{
	Use:   "hera",
	Short: "Deploy Hera (Authentik) for identity and access management",
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()

		log.Info("Starting Hera (Authentik) deployment...")

		composeURL := "https://raw.githubusercontent.com/CodeMonkeyCybersecurity/assets/main/hera/docker-compose.yml"
		composeFile := "/opt/hera/docker-compose.yml"

		// Create target directory
		if err := os.MkdirAll(filepath.Dir(composeFile), 0755); err != nil {
			log.Fatal("Failed to create directory for Hera deployment", zap.Error(err))
		}

		// Download Compose file
		if err := utils.DownloadFile(composeURL, composeFile); err != nil {
			log.Fatal("Failed to download Hera Compose file", zap.Error(err))
		}

		// Validate Docker/Compose
		if err := docker.CheckIfDockerComposeInstalled(); err != nil {
			log.Fatal("Docker Compose is not installed", zap.Error(err))
		}

		// Start Hera
		if err := docker.ComposeUp(filepath.Dir(composeFile)); err != nil {
			log.Fatal("Failed to start Hera stack", zap.Error(err))
		}

		log.Info("✅ Hera has been deployed at https://hera.cybermonkey.net.au 🎉")
	},
}

func init() {
	deployCmd.AddCommand(deployHeraCmd)
}
