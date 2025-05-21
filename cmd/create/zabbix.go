package create

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateZabbixCmd = &cobra.Command{
	Use:   "zabbix",
	Short: "Deploy Zabbix monitoring stack using Docker Compose",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		zap.L().Info("Starting Zabbix installation...")

		if err := deployZabbix(); err != nil {
			zap.L().Error("Zabbix installation failed", zap.Error(err))
			fmt.Println("Zabbix installation failed:", err)
			os.Exit(1)
		}

		zap.L().Info("Zabbix successfully installed")
		fmt.Println("Zabbix successfully deployed at http://localhost:8080")
		return nil
	}),
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
	if err := os.MkdirAll(shared.ZabbixDir, shared.DirPermStandard); err != nil {
		return fmt.Errorf("failed to create %s: %w", shared.ZabbixDir, err)
	}

	// Start the stack
	zap.L().Info("Running docker compose up...")
	if err := docker.ComposeUp(shared.ZabbixComposeYML); err != nil {
		return err
	}

	return nil
}

func init() {

	CreateCmd.AddCommand(CreateZabbixCmd)

}
