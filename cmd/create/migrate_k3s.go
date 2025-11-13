// cmd/create/migrate_k3s.go
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var MigrateK3sCmd = &cobra.Command{
	Use:   "migrate-k3s",
	Short: "Migrate existing K3s cluster to Nomad",
	Long: `Migrate an existing K3s/Kubernetes cluster to HashiCorp Nomad.

This command automates the migration process from K3s to Nomad by:
- Extracting K3s workload definitions
- Converting them to Nomad job specifications
- Setting up equivalent ingress/load balancing
- Optionally preserving persistent volumes
- Registering services with Consul

The migration process is designed to minimize downtime and preserve
application state where possible.

Examples:
  # Basic migration with domain
  eos create migrate-k3s --domain=example.com

  # Dry run to see what would be migrated
  eos create migrate-k3s --domain=example.com --dry-run

  # Migration with ingress and mail proxy
  eos create migrate-k3s --domain=example.com --migrate-ingress --migrate-mail

  # Custom K3s config path
  eos create migrate-k3s --k3s-config=/etc/rancher/k3s --domain=example.com

Migration Steps:
  1. Assessment: Check K3s cluster and Nomad prerequisites
  2. Extraction: Read K3s workload definitions
  3. Conversion: Convert to Nomad job specifications
  4. Deployment: Deploy Nomad jobs
  5. Verification: Verify services are running
  6. Ingress: Setup Caddy/Nginx if requested

Post-Migration:
  After successful migration, you can remove K3s with:
    eos delete k3s

  Monitor your Nomad jobs:
    eos read nomad

Note: This is a one-way migration. Once migrated to Nomad, K3s will be uninstalled.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Parse flags
		domain, _ := cmd.Flags().GetString("domain")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		k3sConfigPath, _ := cmd.Flags().GetString("k3s-config")
		preservePVCs, _ := cmd.Flags().GetBool("preserve-pvcs")
		migrateIngress, _ := cmd.Flags().GetBool("migrate-ingress")
		migrateMailProxy, _ := cmd.Flags().GetBool("migrate-mail")
		datacenter, _ := cmd.Flags().GetString("datacenter")
		region, _ := cmd.Flags().GetString("region")

		// Validate required flags
		if domain == "" && !dryRun {
			return fmt.Errorf("--domain is required for migration (or use --dry-run to test)")
		}

		logger.Info("Starting K3s to Nomad migration",
			zap.String("domain", domain),
			zap.Bool("dry_run", dryRun),
			zap.String("k3s_config_path", k3sConfigPath))

		// Create migration configuration
		config := nomad.K3sMigrationConfig{
			SourceClusterPath: k3sConfigPath,
			PreservePVCs:      preservePVCs,
			MigrateIngress:    migrateIngress,
			MigrateMailProxy:  migrateMailProxy,
			Domain:            domain,
			TargetDatacenter:  datacenter,
			TargetRegion:      region,
			DryRun:            dryRun,
		}

		// Create migration manager
		migrationManager := nomad.NewMigrationManager(logger)

		// Execute migration
		result, err := migrationManager.MigrateK3sToNomad(rc, config)
		if err != nil {
			logger.Error("Migration failed", zap.Error(err))
			return fmt.Errorf("K3s to Nomad migration failed: %w", err)
		}

		// Display results
		logger.Info("Migration completed successfully",
			zap.Int("services_converted", result.ServicesConverted),
			zap.Int("jobs_created", result.JobsCreated),
			zap.Bool("ingress_setup", result.IngressSetup),
			zap.Bool("mail_proxy_setup", result.MailProxySetup))

		if len(result.Errors) > 0 {
			logger.Warn("Migration completed with warnings",
				zap.Strings("errors", result.Errors))
		}

		logger.Info(result.MigrationSummary)

		if dryRun {
			logger.Info("DRY RUN MODE: No changes were made to the system")
		} else {
			logger.Info("Migration successful! Next steps:",
				zap.String("verify_jobs", "eos read nomad"),
				zap.String("remove_k3s", "eos delete k3s"))
		}

		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(MigrateK3sCmd)

	MigrateK3sCmd.Flags().String("domain", "", "Primary domain for the cluster (required)")
	MigrateK3sCmd.Flags().Bool("dry-run", false, "Show what would be migrated without making changes")
	MigrateK3sCmd.Flags().String("k3s-config", "/etc/rancher/k3s", "Path to K3s configuration directory")
	MigrateK3sCmd.Flags().Bool("preserve-pvcs", true, "Preserve persistent volume claims during migration")
	MigrateK3sCmd.Flags().Bool("migrate-ingress", true, "Setup Nomad ingress (Caddy) to replace K3s ingress")
	MigrateK3sCmd.Flags().Bool("migrate-mail", false, "Setup Nginx mail proxy if it was configured in K3s")
	MigrateK3sCmd.Flags().String("datacenter", "dc1", "Target Nomad datacenter")
	MigrateK3sCmd.Flags().String("region", "global", "Target Nomad region")
}
