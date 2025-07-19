// cmd/create/nomad.go

package create

import (
	"fmt"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func init() {
	CreateCmd.AddCommand(createNomadCmd)
	CreateCmd.AddCommand(createNomadIngressCmd)
	CreateCmd.AddCommand(migrateK3sCmd)
	
	// Add configuration flags for Nomad
	createNomadCmd.Flags().String("version", "latest", "Nomad version to install")
	createNomadCmd.Flags().String("datacenter", "dc1", "Nomad datacenter name")
	createNomadCmd.Flags().String("region", "global", "Nomad region name")
	createNomadCmd.Flags().String("node-role", "both", "Node role: client, server, or both")
	createNomadCmd.Flags().Bool("enable-ui", true, "Enable Nomad web UI")
	createNomadCmd.Flags().Bool("skip-configure", false, "Skip configuration phase")
	createNomadCmd.Flags().Bool("skip-verify", false, "Skip verification phase")

	// Add flags for Nomad ingress
	createNomadIngressCmd.Flags().String("domain", "", "Primary domain for ingress")
	createNomadIngressCmd.Flags().Bool("enable-mail", false, "Include Nginx mail proxy")
	createNomadIngressCmd.MarkFlagRequired("domain")

	// Add flags for K3s migration
	migrateK3sCmd.Flags().String("domain", "", "Domain for migrated ingress")
	migrateK3sCmd.Flags().Bool("dry-run", false, "Preview migration without making changes")
	migrateK3sCmd.Flags().Bool("preserve-pvcs", true, "Preserve persistent volume claims")
	migrateK3sCmd.Flags().Bool("migrate-ingress", true, "Migrate ingress to Nomad")
	migrateK3sCmd.Flags().Bool("migrate-mail-proxy", false, "Migrate mail proxy to Nomad")
	migrateK3sCmd.Flags().String("datacenter", "dc1", "Target Nomad datacenter")
	migrateK3sCmd.Flags().String("region", "global", "Target Nomad region")
}

var createNomadCmd = &cobra.Command{
	Use:   "nomad",
	Short: "Install and configure HashiCorp Nomad using SaltStack",
	Long: `Install and configure HashiCorp Nomad orchestrator using SaltStack.
This command deploys Nomad as part of the HashiCorp stack for container orchestration.

Nomad is a workload orchestrator that can manage containerized and non-containerized
applications across on-premise and cloud environments.

The deployment includes:
- Nomad binary installation
- Service configuration
- Consul integration
- Vault integration
- Web UI setup
- Basic security hardening

Prerequisites:
- Running Consul cluster
- Running Vault server
- SaltStack minion configured

Examples:
  eos create nomad                              # Install with defaults
  eos create nomad --version=1.7.2            # Install specific version
  eos create nomad --node-role=server         # Server-only node
  eos create nomad --datacenter=production    # Custom datacenter`,
	RunE: eos_cli.Wrap(runCreateNomad),
}

func runCreateNomad(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Nomad installation with SaltStack")

	// Parse configuration flags
	version, _ := cmd.Flags().GetString("version")
	datacenter, _ := cmd.Flags().GetString("datacenter")
	region, _ := cmd.Flags().GetString("region")
	nodeRole, _ := cmd.Flags().GetString("node-role")
	enableUI, _ := cmd.Flags().GetBool("enable-ui")
	skipConfigure, _ := cmd.Flags().GetBool("skip-configure")
	skipVerify, _ := cmd.Flags().GetBool("skip-verify")

	// Build configuration
	config := &nomad.Config{
		Version:    version,
		Datacenter: datacenter,
		Region:     region,
		NodeRole:   nodeRole,
		EnableUI:   enableUI,
		
		// Integration settings
		ConsulIntegration: true,
		VaultIntegration:  true,
		
		// Security settings
		EnableTLS:    true,
		EnableACL:    true,
		EnableGossip: true,
	}

	// ASSESS - Check prerequisites
	logger.Info("Checking prerequisites for Nomad installation")
	if err := nomad.CheckPrerequisites(rc); err != nil {
		logger.Error("Prerequisites check failed", zap.Error(err))
		return err
	}

	// INTERVENE - Install Nomad using SaltStack
	logger.Info("Installing Nomad using SaltStack")
	if err := nomad.InstallWithSaltStack(rc, config); err != nil {
		logger.Error("Nomad installation failed", zap.Error(err))
		return err
	}

	// Configure Nomad
	if !skipConfigure {
		logger.Info("Configuring Nomad")
		if err := nomad.Configure(rc, config); err != nil {
			logger.Error("Nomad configuration failed", zap.Error(err))
			return err
		}
	}

	// EVALUATE - Verify installation
	if !skipVerify {
		logger.Info("Verifying Nomad installation")
		if err := nomad.Verify(rc, config); err != nil {
			logger.Error("Nomad verification failed", zap.Error(err))
			return err
		}
	}

	logger.Info("Nomad installation completed successfully")
	logger.Info("terminal prompt: ✅ Nomad Installation Complete!")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Service Details:")
	logger.Info("terminal prompt:   - Version: " + version)
	logger.Info("terminal prompt:   - Datacenter: " + datacenter)
	logger.Info("terminal prompt:   - Region: " + region)
	logger.Info("terminal prompt:   - Node Role: " + nodeRole)
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Access URLs:")
	if enableUI {
		logger.Info("terminal prompt:   - Web UI: http://localhost:4646")
	}
	logger.Info("terminal prompt:   - API: http://localhost:4646/v1/")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Next Steps:")
	logger.Info("terminal prompt:   1. Check status: nomad server members")
	logger.Info("terminal prompt:   2. View logs: sudo journalctl -u nomad -f")
	logger.Info("terminal prompt:   3. Deploy jobs: nomad job run <job-file>")
	logger.Info("terminal prompt:   4. Install Hecate: eos create hecate")

	return nil
}

// createNomadIngressCmd sets up Nomad ingress to replace K3s ingress
var createNomadIngressCmd = &cobra.Command{
	Use:   "nomad-ingress",
	Short: "Deploy Nomad ingress with Caddy and Nginx (replaces K3s ingress)",
	Long: `Deploy ingress infrastructure using Nomad jobs with Caddy and Nginx.
This replaces K3s/Kubernetes ingress controllers with Nomad-based alternatives.

Components:
- Caddy for HTTP/HTTPS ingress and reverse proxy
- Nginx for mail proxy (SMTP/IMAP/POP3) 
- Consul Connect for service mesh (optional)
- Automatic SSL certificate management
- Load balancing and health checking

This provides the same ingress capabilities as K3s but using Nomad orchestration.

Prerequisites:
- Running Nomad cluster
- Running Consul cluster
- Domain DNS configured

Examples:
  eos create nomad-ingress --domain=example.com
  eos create nomad-ingress --domain=mail.example.com --enable-mail`,
	RunE: eos_cli.Wrap(runCreateNomadIngress),
}

func runCreateNomadIngress(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Setting up Nomad ingress infrastructure")

	domain, _ := cmd.Flags().GetString("domain")
	enableMail, _ := cmd.Flags().GetBool("enable-mail")
	
	// Generate Nomad ingress jobs
	generator := nomad.NewJobGenerator(logger)
	
	// Setup Caddy ingress
	logger.Info("Generating Caddy ingress job specification")
	caddyConfig := nomad.GetDefaultCaddyConfig()
	caddyConfig.Domain = domain
	
	caddyJob, err := generator.GenerateCaddyIngressJob(rc, caddyConfig)
	if err != nil {
		logger.Error("Failed to generate Caddy ingress job", zap.Error(err))
		return err
	}
	
	// Deploy Caddy ingress job
	logger.Info("Deploying Caddy ingress to Nomad cluster")
	if err := generator.DeployNomadJob(rc, caddyJob); err != nil {
		logger.Error("Failed to deploy Caddy ingress", zap.Error(err))
		return err
	}
	
	// Setup Nginx mail proxy if requested
	if enableMail {
		logger.Info("Generating Nginx mail proxy job specification")
		nginxConfig := nomad.GetDefaultNginxConfig()
		nginxConfig.Domain = domain
		
		nginxJob, err := generator.GenerateNginxMailJob(rc, nginxConfig)
		if err != nil {
			logger.Error("Failed to generate Nginx mail proxy job", zap.Error(err))
			return err
		}
		
		// Deploy Nginx mail proxy job
		logger.Info("Deploying Nginx mail proxy to Nomad cluster")
		if err := generator.DeployNomadJob(rc, nginxJob); err != nil {
			logger.Error("Failed to deploy Nginx mail proxy", zap.Error(err))
			return err
		}
	}

	logger.Info("Nomad ingress deployment completed successfully")
	logger.Info("terminal prompt: ✅ Nomad Ingress Deployment Complete!")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Ingress Details:")
	logger.Info("terminal prompt:   - Domain: " + domain)
	logger.Info("terminal prompt:   - Caddy HTTP/HTTPS: Deployed")
	if enableMail {
		logger.Info("terminal prompt:   - Nginx Mail Proxy: Deployed")
	}
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Next Steps:")
	logger.Info("terminal prompt:   1. Check job status: nomad job status caddy-ingress")
	if enableMail {
		logger.Info("terminal prompt:   2. Check mail proxy: nomad job status nginx-mail-proxy")
	}
	logger.Info("terminal prompt:   3. Configure DNS: Point " + domain + " to Nomad cluster")
	logger.Info("terminal prompt:   4. Deploy backend services: nomad job run <service.hcl>")
	
	return nil
}

// migrateK3sCmd migrates existing K3s cluster to Nomad
var migrateK3sCmd = &cobra.Command{
	Use:   "migrate-k3s",
	Short: "Migrate K3s cluster to Nomad",
	Long: `Migrate an existing K3s/Kubernetes cluster to Nomad orchestration.
This command extracts workloads from K3s and converts them to equivalent Nomad jobs.

Migration process:
1. Extract K3s deployments, services, and configurations
2. Convert Kubernetes resources to Nomad job specifications
3. Setup Consul service discovery to replace Kubernetes services
4. Deploy Caddy/Nginx ingress to replace K3s ingress
5. Migrate persistent volumes and secrets
6. Verify migration and optionally remove K3s

The migration preserves application functionality while moving to simpler Nomad orchestration.

Prerequisites:
- Running K3s cluster (source)
- Running Nomad cluster (target)
- Running Consul cluster
- kubectl access to K3s cluster

Examples:
  eos create migrate-k3s --domain=example.com --dry-run
  eos create migrate-k3s --domain=example.com --migrate-ingress --migrate-mail-proxy
  eos create migrate-k3s --domain=example.com --datacenter=production`,
	RunE: eos_cli.Wrap(runMigrateK3s),
}

func runMigrateK3s(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting K3s to Nomad migration")

	domain, _ := cmd.Flags().GetString("domain")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	preservePVCs, _ := cmd.Flags().GetBool("preserve-pvcs")
	migrateIngress, _ := cmd.Flags().GetBool("migrate-ingress")
	migrateMailProxy, _ := cmd.Flags().GetBool("migrate-mail-proxy")
	datacenter, _ := cmd.Flags().GetString("datacenter")
	region, _ := cmd.Flags().GetString("region")
	
	// Setup migration configuration
	migrationConfig := nomad.K3sMigrationConfig{
		Domain:              domain,
		DryRun:              dryRun,
		PreservePVCs:        preservePVCs,
		MigrateIngress:      migrateIngress,
		MigrateMailProxy:    migrateMailProxy,
		TargetDatacenter:    datacenter,
		TargetRegion:        region,
	}
	
	// Perform migration
	logger.Info("Initializing migration manager")
	migrationManager := nomad.NewMigrationManager(logger)
	
	logger.Info("Executing K3s to Nomad migration",
		zap.Bool("dry_run", dryRun),
		zap.String("target_datacenter", datacenter))
	
	result, err := migrationManager.MigrateK3sToNomad(rc, migrationConfig)
	if err != nil {
		logger.Error("K3s migration failed", zap.Error(err))
		return err
	}
	
	// Display migration results
	logger.Info("K3s to Nomad migration completed")
	logger.Info("terminal prompt: ✅ K3s Migration Complete!")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Migration Summary:")
	logger.Info("terminal prompt:   - Services converted: " + fmt.Sprintf("%d", result.ServicesConverted))
	logger.Info("terminal prompt:   - Nomad jobs created: " + fmt.Sprintf("%d", result.JobsCreated))
	logger.Info("terminal prompt:   - Ingress migrated: " + fmt.Sprintf("%t", result.IngressSetup))
	logger.Info("terminal prompt:   - Mail proxy migrated: " + fmt.Sprintf("%t", result.MailProxySetup))
	
	if len(result.Errors) > 0 {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Migration Warnings:")
		for _, errMsg := range result.Errors {
			logger.Info("terminal prompt:   - " + errMsg)
		}
	}
	
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Next Steps:")
	logger.Info("terminal prompt:   1. Verify services: nomad job status")
	logger.Info("terminal prompt:   2. Check Consul services: consul catalog services")
	if migrateIngress {
		logger.Info("terminal prompt:   3. Test ingress: curl " + domain)
	}
	if !dryRun {
		logger.Info("terminal prompt:   4. Remove K3s (after verification): eos delete k3s")
	}
	
	return nil
}