package create

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateZabbixCmd = &cobra.Command{
	Use:   "zabbix",
	Short: "Deploy Zabbix monitoring stack using Docker Compose",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("Starting Zabbix installation...")

		if err := deployZabbix(rc); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Zabbix installation failed", zap.Error(err))
			fmt.Println("Zabbix installation failed:", err)
			os.Exit(1)
		}

		otelzap.Ctx(rc.Ctx).Info("Zabbix successfully installed")
		fmt.Println("Zabbix successfully deployed at http://localhost:8080")
		return nil
	}),
}

func deployZabbix(rc *eos_io.RuntimeContext) error {

	// Ensure Docker is installed and running (install if needed)
	if err := container.EnsureDockerInstalled(rc); err != nil {
		return fmt.Errorf("docker dependency check failed: %w", err)
	}

	// Ensure Docker Compose is installed
	if err := container.CheckIfDockerComposeInstalled(rc); err != nil {
		return fmt.Errorf("docker compose check failed: %w", err)
	}

	// Create target directory
	if err := os.MkdirAll(shared.ZabbixDir, shared.DirPermStandard); err != nil {
		return fmt.Errorf("failed to create %s: %w", shared.ZabbixDir, err)
	}

	// Start the stack
	otelzap.Ctx(rc.Ctx).Info("Running docker compose up...")
	if err := container.ComposeUp(rc, shared.ZabbixComposeYML); err != nil {
		return err
	}

	return nil
}

func init() {

	CreateCmd.AddCommand(CreateZabbixCmd)

}
