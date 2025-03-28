package deploy

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var zabbixCmd = &cobra.Command{
	Use:   "zabbix",
	Short: "Deploy Zabbix monitoring stack using Docker Compose",
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("Starting Zabbix installation...")

		if err := deployZabbix(); err != nil {
			log.Error("Zabbix installation failed", zap.Error(err))
			fmt.Println("Zabbix installation failed:", err)
			os.Exit(1)
		}

		log.Info("Zabbix successfully installed")
		fmt.Println("Zabbix successfully deployed at http://localhost:8080")
	},
}

func deployZabbix() error {

	// Ensure Docker is installed
	if err := docker.CheckIfDockerInstalled(); err != nil {
		return fmt.Errorf("docker check failed: %w", err)
	}

	// Ensure Docker Compose is installed
	if err := docker.CheckIfDockerComposeInstalled(); err != nil {
		return fmt.Errorf("docker-compose check failed: %w", err)
	}

	// Create target directory
	if err := os.MkdirAll(config.ZabbixDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", config.ZabbixDir, err)
	}

	// Start the stack
	log.Info("Running docker compose up...")
	if err := docker.RunCommand("docker", "compose", "-f", config.ZabbixComposeYML, "up", "-d"); err != nil {
		return fmt.Errorf("failed to run docker compose: %w", err)
	}

	return nil
}
