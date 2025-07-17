// cmd/create/nomad.go

package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func init() {
	CreateCmd.AddCommand(createNomadCmd)
	
	// Add configuration flags
	createNomadCmd.Flags().String("version", "latest", "Nomad version to install")
	createNomadCmd.Flags().String("datacenter", "dc1", "Nomad datacenter name")
	createNomadCmd.Flags().String("region", "global", "Nomad region name")
	createNomadCmd.Flags().String("node-role", "both", "Node role: client, server, or both")
	createNomadCmd.Flags().Bool("enable-ui", true, "Enable Nomad web UI")
	createNomadCmd.Flags().Bool("skip-configure", false, "Skip configuration phase")
	createNomadCmd.Flags().Bool("skip-verify", false, "Skip verification phase")
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