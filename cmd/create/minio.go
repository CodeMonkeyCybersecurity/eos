package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/minio"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var minioCmd = &cobra.Command{
	Use:   "minio",
	Short: "Deploy MinIO object storage to Nomad cluster",
	Long: `Deploy MinIO object storage using the Eos framework's  → Terraform → Nomad workflow.

This command will:
- Deploy MinIO using Terraform to manage Nomad jobs and Consul services
- Configure dynamic credentials via Vault
- Set up Prometheus metrics collection

Prerequisites:
- Ubuntu 22.04 hosts
- Terraform, Nomad, Vault, and Consul installed
- External disk mounted at /mnt/external_disk
- Vault KV v2 engine enabled at 'kv/'`,

	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("Starting MinIO deployment")

		// Get deployment options from flags
		datacenter, _ := cmd.Flags().GetString("datacenter")
		storagePath, _ := cmd.Flags().GetString("storage-path")
		apiPort, _ := cmd.Flags().GetInt("api-port")
		consolePort, _ := cmd.Flags().GetInt("console-port")
		skipTerraform, _ := cmd.Flags().GetBool("skip-terraform")

		// Create deployment options
		opts := &minio.DeploymentOptions{
			Datacenter:    datacenter,
			StoragePath:   storagePath,
			APIPort:       apiPort,
			ConsolePort:   consolePort,
			SkipTerraform: skipTerraform,
		}

		// Execute deployment
		deployer := minio.NewDeployer()
		if err := deployer.Deploy(rc, opts); err != nil {
			logger.Error("MinIO deployment failed", zap.Error(err))
			return err
		}

		logger.Info("MinIO deployment completed successfully")
		return nil
	}),
}

func init() {
	// Add command flags
	minioCmd.Flags().String("datacenter", "dc1", "Nomad datacenter")
	minioCmd.Flags().String("storage-path", "/mnt/external_disk", "Storage path for MinIO data")
	minioCmd.Flags().Int("api-port", 9123, "MinIO API port")
	minioCmd.Flags().Int("console-port", 8123, "MinIO console port")
	minioCmd.Flags().Bool("skip-terraform", false, "Skip Terraform deployment (useful for manual Nomad job submission)")

	// Register with parent command
	CreateCmd.AddCommand(minioCmd)
}
