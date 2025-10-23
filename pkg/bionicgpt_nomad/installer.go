// pkg/bionicgpt_nomad/installer.go - Main 9-phase enterprise installer

package bionicgpt_nomad

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewEnterpriseInstaller creates a new enterprise installer
func NewEnterpriseInstaller(rc *eos_io.RuntimeContext, config *EnterpriseConfig) *EnterpriseInstaller {
	// Apply defaults
	if config.Namespace == "" {
		config.Namespace = DefaultNamespace
	}
	if config.SuperadminGroup == "" {
		config.SuperadminGroup = DefaultSuperadminGroup
	}
	if config.DemoGroup == "" {
		config.DemoGroup = DefaultDemoGroup
	}
	if config.GroupPrefix == "" {
		config.GroupPrefix = DefaultGroupPrefix
	}
	if config.NomadAddress == "" {
		config.NomadAddress = DefaultNomadAddress
	}
	if config.ConsulAddress == "" {
		config.ConsulAddress = DefaultConsulAddress
	}
	if config.LocalEmbeddingsModel == "" {
		config.LocalEmbeddingsModel = DefaultLocalEmbeddingsModel
	}

	return &EnterpriseInstaller{
		rc:     rc,
		config: config,
	}
}

// Install runs the 9-phase enterprise installation process
func (ei *EnterpriseInstaller) Install() error {
	logger := otelzap.Ctx(ei.rc.Ctx)
	startTime := time.Now()

	logger.Info("================================================================================")
	logger.Info("BionicGPT Enterprise Deployment - Nomad + Hecate + Authentik")
	logger.Info("================================================================================")
	logger.Info("Configuration",
		zap.String("domain", ei.config.Domain),
		zap.String("cloud_node", ei.config.CloudNode),
		zap.String("auth_url", ei.config.AuthURL),
		zap.Bool("dry_run", ei.config.DryRun))

	// Phase 0: Check prerequisites (one-time manual steps)
	logger.Info("Phase 0: Checking prerequisites")
	if err := ei.checkPrerequisites(); err != nil {
		return fmt.Errorf("prerequisites not met: %w\n\n%s", err, getPrerequisitesHelp())
	}
	logger.Info("✓ Prerequisites check passed")

	// Phase 3: Preflight checks (automated validation)
	logger.Info("Phase 3: Running preflight checks")
	if err := ei.Preflight(); err != nil {
		return fmt.Errorf("preflight checks failed: %w", err)
	}
	logger.Info("✓ Preflight checks passed")

	// Phase 4: Configure Authentik
	logger.Info("Phase 4: Configuring Authentik")
	if err := ei.ConfigureAuthentik(); err != nil {
		return fmt.Errorf("authentik configuration failed: %w", err)
	}
	logger.Info("✓ Authentik configuration complete")

	// Phase 5: Setup Consul
	logger.Info("Phase 5: Setting up Consul service discovery")
	if err := ei.SetupConsul(); err != nil {
		return fmt.Errorf("consul setup failed: %w", err)
	}
	logger.Info("✓ Consul setup complete")

	if ei.config.DryRun {
		logger.Info("================================================================================")
		logger.Info("DRY RUN: Stopping before Nomad deployment")
		logger.Info("================================================================================")
		logger.Info("All preflight checks passed. Ready to deploy.")
		return nil
	}

	// Phase 6: Deploy to Nomad
	logger.Info("Phase 6: Deploying to Nomad")
	if err := ei.DeployNomad(); err != nil {
		return fmt.Errorf("nomad deployment failed: %w", err)
	}
	logger.Info("✓ Nomad deployment complete")

	// Phase 7: Configure Hecate
	logger.Info("Phase 7: Configuring Hecate reverse proxy")
	if err := ei.ConfigureHecate(); err != nil {
		return fmt.Errorf("hecate configuration failed: %w", err)
	}
	logger.Info("✓ Hecate configuration complete")

	// Phase 8: Wait for healthy
	if !ei.config.SkipHealthCheck {
		logger.Info("Phase 8: Waiting for services to become healthy")
		if err := ei.WaitForHealthy(5 * time.Minute); err != nil {
			return fmt.Errorf("health checks failed: %w", err)
		}
		logger.Info("✓ All services healthy")
	} else {
		logger.Info("Phase 8: Skipping health checks (--skip-health-check flag set)")
	}

	// Success
	duration := time.Since(startTime)
	logger.Info("================================================================================")
	logger.Info("BionicGPT Enterprise Deployment Completed Successfully")
	logger.Info("================================================================================")
	logger.Info("Deployment summary",
		zap.Duration("duration", duration),
		zap.String("domain", ei.config.Domain),
		zap.String("auth_url", ei.config.AuthURL))

	return nil
}

// checkPrerequisites checks one-time manual prerequisites
func (ei *EnterpriseInstaller) checkPrerequisites() error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Check 1: Tailscale installed and running
	logger.Debug("Checking Tailscale")
	if err := ei.checkTailscale(); err != nil {
		return fmt.Errorf("tailscale check failed: %w", err)
	}

	// Check 2: Authentik API token in Vault
	logger.Debug("Checking Authentik API token in Vault")
	if err := ei.checkAuthentikToken(); err != nil {
		return fmt.Errorf("authentik token check failed: %w", err)
	}

	// Check 3: Azure OpenAI credentials in Vault (if not using local embeddings only)
	if ei.config.AzureEndpoint != "" || ei.config.AzureChatDeployment != "" {
		logger.Debug("Checking Azure OpenAI credentials in Vault")
		if err := ei.checkAzureCredentials(); err != nil {
			return fmt.Errorf("azure credentials check failed: %w", err)
		}
	}

	return nil
}

// getPrerequisitesHelp returns help text for prerequisites
func getPrerequisitesHelp() string {
	return `
Prerequisites Not Met
======================

Before running 'eos create bionicgpt', complete these one-time setup steps:

1. Install and Connect Tailscale (Both Nodes)
   -------------------------------------------
   Cloud node:
     curl -fsSL https://tailscale.com/install.sh | sh
     sudo tailscale up

   Local node:
     curl -fsSL https://tailscale.com/install.sh | sh
     sudo tailscale up

   Verify: tailscale status

2. Create Authentik API Token
   ---------------------------
   1. Navigate to: https://auth.example.com/if/admin/#/core/tokens
   2. Create token with identifier: eos-automation
   3. Store in Vault:
      vault kv put secret/bionicgpt/authentik \\
        api_key="YOUR_TOKEN_HERE" \\
        base_url="https://auth.example.com"

3. Store Azure OpenAI Credentials (Optional)
   ------------------------------------------
   vault kv put secret/bionicgpt/azure \\
     endpoint="https://YOUR_RESOURCE.openai.azure.com" \\
     api_key="YOUR_AZURE_API_KEY" \\
     chat_deployment="YOUR_DEPLOYMENT_NAME"

4. Verify Consul Access
   ---------------------
   From local node:
     CLOUD_IP=$(tailscale ip CLOUD_NODE_NAME)
     curl http://$CLOUD_IP:8500/v1/status/leader

5. Verify Caddy Admin API
   -----------------------
   From local node:
     curl http://$CLOUD_IP:2019/

After completing these steps, run 'eos create bionicgpt' again.

For more details: https://wiki.cybermonkey.net.au/bionicgpt/enterprise-setup
`
}

// Validate validates the configuration
func (c *EnterpriseConfig) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("domain is required (use --domain flag)")
	}
	if c.CloudNode == "" {
		return fmt.Errorf("cloud node is required (use --cloud-node flag)")
	}
	if c.AuthURL == "" {
		return fmt.Errorf("authentik URL is required (use --auth-url flag)")
	}

	// Either Azure OpenAI or local embeddings should be configured for chat
	if c.AzureEndpoint == "" && c.AzureChatDeployment == "" {
		return fmt.Errorf("azure chat deployment is required (use --azure-endpoint and --azure-chat-deployment flags)")
	}

	return nil
}
