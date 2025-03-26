// cmd/install/zabbix.go

package install

import (
	"fmt"
	"os"
	"path/filepath"

  	"eos/pkg/utils"
	"eos/pkg/config"
	"eos/pkg/logger"

	"go.uber.org/zap"
	"github.com/spf13/cobra"

)

var log *zap.Logger

var installZabbixCmd = &cobra.Command{
	Use:   "zabbix",
	Short: "Install Zabbix monitoring stack using Docker Compose",
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("Starting Zabbix installation...")

		if err := installZabbix(); err != nil {
			log.Error("Zabbix installation failed", zap.Error(err))
			fmt.Println("Zabbix installation failed:", err)
			os.Exit(1)
		}

		log.Info("Zabbix successfully installed")
		fmt.Println("Zabbix successfully deployed at http://localhost:8080")
	},
}

func installZabbix() error {

	// Ensure Docker is installed
	if err := utils.CheckIfDockerInstalled(); err != nil {
		return fmt.Errorf("docker check failed: %w", err)
	}

	// Ensure Docker Compose is installed
	if err := utils.CheckIfDockerComposeInstalled(); err != nil {
		return fmt.Errorf("docker-compose check failed: %w", err)
	}

	// Create target directory
	if err := os.MkdirAll(config.ZabbixDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", config.ZabbixDir, err)
	}



	// Start the stack
	log.Info("Running docker compose up...")
	if err := utils.RunCommand("docker", "compose", "-f", config.ZabbixComposeYML, "up", "-d"); err != nil {
		return fmt.Errorf("failed to run docker compose: %w", err)
	}

	return nil
}

func init() {
	installCmd.AddCommand(installZabbixCmd)
}
