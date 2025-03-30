// cmd/create/hera.go

package create

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateHeraCmd = &cobra.Command{
	Use:   "hera",
	Short: "Deploy Hera (Authentik) for self-service identity & access management",
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()
		log.Info("Starting Hera (Authentik) deployment...")

		if err := deployHera(); err != nil {
			log.Error("Hera deployment failed", zap.Error(err))
			fmt.Println("Hera deployment failed:", err)
			os.Exit(1)
		}

		log.Info("✅ Hera successfully deployed")
		fmt.Println("Hera available at https://hera.domain.com")
	},
}

func deployHera() error {
	log := logger.GetLogger()

	// Ensure Docker is installed
	if err := docker.CheckIfDockerInstalled(); err != nil {
		return fmt.Errorf("docker check failed: %w", err)
	}

	// Ensure Docker Compose is installed
	if err := docker.CheckIfDockerComposeInstalled(); err != nil {
		return fmt.Errorf("docker-compose check failed: %w", err)
	}

	// Create target directory
	if err := os.MkdirAll(config.HeraDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", config.HeraDir, err)
	}

	// Run docker compose up
	log.Info("Running docker compose up...")
	if err := docker.RunCommand("docker", "compose", "-f", config.HeraComposeYML, "up", "-d"); err != nil {
		return fmt.Errorf("failed to run docker compose: %w", err)
	}

	return nil
}

func init() {

	CreateCmd.AddCommand(CreateHeraCmd)

}
