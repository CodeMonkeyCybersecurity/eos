// cmd/create/consul_orchestrated.go
package create

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/orchestrator"
	orchNomad "github.com/CodeMonkeyCybersecurity/eos/pkg/orchestrator/nomad"
	orchSalt "github.com/CodeMonkeyCybersecurity/eos/pkg/orchestrator/salt"
	orchTerraform "github.com/CodeMonkeyCybersecurity/eos/pkg/orchestrator/terraform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Feature flag to enable orchestrated deployment
var useOrchestration = os.Getenv("EOS_USE_ORCHESTRATION") == "true"

var createConsulOrchestratedCmd = &cobra.Command{
	Use:   "consul-orchestrated",
	Short: "Deploy Consul via orchestration stack (Salt → Terraform → Nomad)",
	Long: `Deploy HashiCorp Consul using the full orchestration pipeline.

This command uses the EOS orchestration stack to deploy Consul:
1. Salt configures the base system (users, directories, configs)
2. Terraform creates Nomad job definitions
3. Nomad runs Consul as a containerized service

Features:
• Declarative configuration management
• Automated rollback on failure
• State tracking and reconciliation
• Zero-downtime updates
• Comprehensive error handling`,
	Example: `  # Deploy Consul with default settings
  eos create consul-orchestrated

  # Deploy with custom datacenter
  eos create consul-orchestrated --datacenter us-west-1

  # Preview generated configurations without applying
  eos create consul-orchestrated --dry-run --show-salt --show-terraform

  # Deploy with specific bootstrap expect
  eos create consul-orchestrated --bootstrap-expect 3 --server-mode`,
	RunE: eos_cli.Wrap(runCreateConsulOrchestrated),
}

func init() {
	// Only register if orchestration is enabled
	if useOrchestration {
		CreateCmd.AddCommand(createConsulOrchestratedCmd)
	}
	
	// Configuration flags
	createConsulOrchestratedCmd.Flags().String("datacenter", "dc1", "Consul datacenter name")
	createConsulOrchestratedCmd.Flags().Int("bootstrap-expect", 1, "Number of servers to wait for before bootstrapping")
	createConsulOrchestratedCmd.Flags().Bool("server-mode", true, "Run Consul in server mode")
	createConsulOrchestratedCmd.Flags().Bool("ui-enabled", true, "Enable Consul web UI")
	createConsulOrchestratedCmd.Flags().String("encryption-key", "", "Gossip encryption key (generated if not provided)")
	createConsulOrchestratedCmd.Flags().Bool("tls-enabled", false, "Enable TLS for Consul communication")
	createConsulOrchestratedCmd.Flags().String("version", "1.17.0", "Consul version to deploy")
	
	// Vault integration
	createConsulOrchestratedCmd.Flags().Bool("vault-integration", false, "Enable Vault integration")
	createConsulOrchestratedCmd.Flags().String("vault-addr", "http://localhost:8200", "Vault server address")
	
	// Orchestration flags
	createConsulOrchestratedCmd.Flags().Bool("dry-run", false, "Generate configs without applying")
	createConsulOrchestratedCmd.Flags().Bool("show-salt", false, "Display generated Salt states")
	createConsulOrchestratedCmd.Flags().Bool("show-terraform", false, "Display generated Terraform config")
	createConsulOrchestratedCmd.Flags().Bool("show-nomad", false, "Display generated Nomad job spec")
	createConsulOrchestratedCmd.Flags().Bool("auto-approve", false, "Skip approval prompts")
	createConsulOrchestratedCmd.Flags().Duration("timeout", 10*time.Minute, "Deployment timeout")
	
	// Backend configuration
	createConsulOrchestratedCmd.Flags().String("salt-master", "localhost", "Salt master address")
	createConsulOrchestratedCmd.Flags().String("nomad-addr", "http://localhost:4646", "Nomad server address")
	createConsulOrchestratedCmd.Flags().String("terraform-workspace", "/var/lib/eos/terraform", "Terraform workspace directory")
}

func runCreateConsulOrchestrated(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Consul deployment via orchestration pipeline")

	// Parse flags
	datacenter, _ := cmd.Flags().GetString("datacenter")
	bootstrapExpect, _ := cmd.Flags().GetInt("bootstrap-expect")
	serverMode, _ := cmd.Flags().GetBool("server-mode")
	uiEnabled, _ := cmd.Flags().GetBool("ui-enabled")
	encryptionKey, _ := cmd.Flags().GetString("encryption-key")
	tlsEnabled, _ := cmd.Flags().GetBool("tls-enabled")
	version, _ := cmd.Flags().GetString("version")
	
	vaultIntegration, _ := cmd.Flags().GetBool("vault-integration")
	vaultAddr, _ := cmd.Flags().GetString("vault-addr")
	
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	showSalt, _ := cmd.Flags().GetBool("show-salt")
	showTerraform, _ := cmd.Flags().GetBool("show-terraform")
	showNomad, _ := cmd.Flags().GetBool("show-nomad")
	autoApprove, _ := cmd.Flags().GetBool("auto-approve")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	
	saltMaster, _ := cmd.Flags().GetString("salt-master")
	nomadAddr, _ := cmd.Flags().GetString("nomad-addr")
	terraformWorkspace, _ := cmd.Flags().GetString("terraform-workspace")

	// Generate encryption key if not provided
	if encryptionKey == "" && serverMode {
		logger.Info("Generating Consul encryption key")
		key, err := consul.GenerateGossipKey()
		if err != nil {
			return fmt.Errorf("failed to generate encryption key: %w", err)
		}
		encryptionKey = key
		logger.Info("Generated encryption key successfully")
	}

	// Create component configuration
	consulComponent := orchestrator.Component{
		Name:    "consul",
		Type:    orchestrator.ServiceType,
		Version: version,
		Config: orchestrator.ConsulConfig{
			Datacenter:      datacenter,
			BootstrapExpect: bootstrapExpect,
			UIEnabled:       uiEnabled,
			Ports: orchestrator.Ports{
				HTTP: shared.PortConsul,
				DNS:  8600,
			},
			VaultIntegration: vaultIntegration,
			VaultAddr:        vaultAddr,
			ServerMode:       serverMode,
			EncryptionKey:    encryptionKey,
			TLSEnabled:       tlsEnabled,
		},
		Labels: map[string]string{
			"managed-by": "eos",
			"component":  "consul",
		},
	}

	// Initialize orchestration components
	logger.Info("Initializing orchestration pipeline")
	
	// Create Salt client
	saltClient := orchSalt.NewClient(rc, orchSalt.Config{
		MasterAddress: saltMaster,
		FileRoots:     "/srv/salt",
		PillarRoots:   "/srv/pillar",
		Environment:   "base",
		Timeout:       5 * time.Minute,
	})
	
	// Create Terraform provider
	terraformProvider := orchTerraform.NewProvider(rc, orchTerraform.Config{
		WorkspaceDir:   terraformWorkspace,
		StateBackend:   "consul",
		BackendConfig: map[string]string{
			"address": fmt.Sprintf("localhost:%d", shared.PortConsul),
			"path":    "terraform/consul/state",
		},
		AutoApprove: autoApprove,
		Parallelism: 10,
	})
	
	// Create Nomad client
	nomadClient, err := orchNomad.NewClient(rc, orchNomad.Config{
		Address:   nomadAddr,
		Region:    "global",
		Namespace: "default",
		Timeout:   30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to create Nomad client: %w", err)
	}

	// Create pipeline
	pipeline := orchestrator.NewPipeline(rc,
		orchestrator.WithSalt(saltClient),
		orchestrator.WithTerraform(terraformProvider),
		orchestrator.WithNomad(nomadClient),
		orchestrator.WithConfig(orchestrator.PipelineConfig{
			DryRun:      dryRun,
			AutoApprove: autoApprove,
			Timeout:     timeout,
		}),
	)

	// Preview configurations if requested
	if showSalt || showTerraform || showNomad {
		if err := previewConfigurations(rc, pipeline, consulComponent, showSalt, showTerraform, showNomad); err != nil {
			return err
		}
		
		if dryRun {
			logger.Info("Dry run complete - no changes were applied")
			return nil
		}
	}

	// Confirm deployment
	if !autoApprove && !dryRun {
		logger.Info("terminal prompt: Deploy Consul with the above configuration? (yes/no)")
		confirm, err := eos_io.PromptInput(rc, "Deploy? (yes/no): ", "yes/no")
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		if confirm != "yes" {
			logger.Info("Deployment cancelled by user")
			return nil
		}
	}

	// Deploy through pipeline
	logger.Info("Starting deployment through orchestration pipeline")
	deployment, err := pipeline.Deploy(context.Background(), consulComponent)
	if err != nil {
		// Check if it's an orchestration error with remediation
		if orchErr, ok := err.(*orchestrator.OrchestrationError); ok {
			logger.Error("Orchestration failed",
				zap.String("layer", string(orchErr.Layer)),
				zap.String("phase", string(orchErr.Phase)),
				zap.String("remediation", orchErr.Remediation))
			return fmt.Errorf("%s: %w", orchErr.Error(), orchErr.Original)
		}
		
		// Check if it's an error chain
		if errChain, ok := err.(*orchestrator.ErrorChain); ok {
			logger.Error("Multiple orchestration errors occurred")
			for _, orchErr := range errChain.Errors {
				logger.Error("Orchestration error",
					zap.String("layer", string(orchErr.Layer)),
					zap.String("phase", string(orchErr.Phase)),
					zap.String("message", orchErr.Message),
					zap.String("remediation", orchErr.Remediation))
			}
			return fmt.Errorf("orchestration failed with multiple errors: %w", err)
		}
		
		return fmt.Errorf("deployment failed: %w", err)
	}

	// Wait for deployment to be healthy
	logger.Info("Waiting for deployment to become healthy",
		zap.String("deployment_id", deployment.ID))
	
	if err := pipeline.WaitForHealthy(context.Background(), deployment, 5*time.Minute); err != nil {
		logger.Error("Deployment health check failed", zap.Error(err))
		return fmt.Errorf("deployment is unhealthy: %w", err)
	}

	// Display success information
	displayDeploymentSuccess(rc, deployment)

	return nil
}

func previewConfigurations(rc *eos_io.RuntimeContext, pipeline orchestrator.Pipeline, component orchestrator.Component, showSalt, showTerraform, showNomad bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	if showSalt {
		logger.Info("=== Generated Salt States ===")
		saltPreview, err := pipeline.PreviewSalt(component)
		if err != nil {
			return fmt.Errorf("failed to preview Salt states: %w", err)
		}
		fmt.Println(saltPreview)
		fmt.Println()
	}
	
	if showTerraform {
		logger.Info("=== Generated Terraform Configuration ===")
		tfPreview, err := pipeline.PreviewTerraform(component)
		if err != nil {
			return fmt.Errorf("failed to preview Terraform config: %w", err)
		}
		fmt.Println(tfPreview)
		fmt.Println()
	}
	
	if showNomad {
		logger.Info("=== Generated Nomad Job Specification ===")
		nomadPreview, err := pipeline.PreviewNomad(component)
		if err != nil {
			return fmt.Errorf("failed to preview Nomad job: %w", err)
		}
		fmt.Println(nomadPreview)
		fmt.Println()
	}
	
	return nil
}

func displayDeploymentSuccess(rc *eos_io.RuntimeContext, deployment *orchestrator.Deployment) {
	logger := otelzap.Ctx(rc.Ctx)
	
	config := deployment.Component.Config.(orchestrator.ConsulConfig)
	
	logger.Info("")
	logger.Info("╔══════════════════════════════════════════════════════════════════╗")
	logger.Info("║            CONSUL DEPLOYED SUCCESSFULLY (ORCHESTRATED)            ║")
	logger.Info("╚══════════════════════════════════════════════════════════════════╝")
	logger.Info("")
	logger.Info("📋 Deployment Details:")
	logger.Info(fmt.Sprintf("   • Deployment ID: %s", deployment.ID))
	logger.Info(fmt.Sprintf("   • Datacenter:    %s", config.Datacenter))
	logger.Info(fmt.Sprintf("   • Server Mode:   %v", config.ServerMode))
	logger.Info(fmt.Sprintf("   • UI Enabled:    %v", config.UIEnabled))
	logger.Info("")
	logger.Info("🌐 Access Points:")
	logger.Info(fmt.Sprintf("   • Web UI:        http://consul.service.consul:%d/ui", config.Ports.HTTP))
	logger.Info(fmt.Sprintf("   • HTTP API:      http://consul.service.consul:%d", config.Ports.HTTP))
	logger.Info(fmt.Sprintf("   • DNS Interface: consul.service.consul:%d", config.Ports.DNS))
	logger.Info("")
	logger.Info("🔧 Management Commands:")
	logger.Info("   • Check status:      nomad job status consul")
	logger.Info("   • View logs:         nomad alloc logs <alloc-id>")
	logger.Info("   • Update config:     eos update consul --component consul")
	logger.Info("   • Rollback:          eos rollback deployment " + deployment.ID)
	logger.Info("")
	
	if deployment.Outputs != nil {
		logger.Info("📊 Deployment Outputs:")
		for key, value := range deployment.Outputs {
			logger.Info(fmt.Sprintf("   • %s: %s", key, value))
		}
		logger.Info("")
	}
	
	logger.Info("✅ Next Steps:")
	logger.Info("   1. Verify Consul cluster health: consul members")
	logger.Info("   2. Configure ACLs if needed: eos update consul acl --enable")
	logger.Info("   3. Register services: consul services register <service.json>")
	
	if config.VaultIntegration {
		logger.Info("   4. Configure Vault backend: vault write consul/config/access address=" + 
			fmt.Sprintf("consul.service.consul:%d", config.Ports.HTTP))
	}
	
	logger.Info("")
	logger.Info("═══════════════════════════════════════════════════════════════════")
}