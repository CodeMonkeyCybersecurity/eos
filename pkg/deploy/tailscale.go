package deploy

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/network"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeployTailscale deploys Tailscale infrastructure from cobra command
// Migrated from cmd/create/infrastructure.go deployTailscaleInfrastructure
func DeployTailscale(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Get configuration from command flags
	logger.Info("Assessing Tailscale deployment configuration")

	// Get command flags
	hostname, _ := cmd.Flags().GetString("hostname")
	advertiseRoutes, _ := cmd.Flags().GetStringSlice("advertise-routes")
	acceptRoutes, _ := cmd.Flags().GetBool("accept-routes")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	terraformDir, _ := cmd.Flags().GetString("terraform-dir")
	vaultPath, _ := cmd.Flags().GetString("vault-path")
	useExitNode, _ := cmd.Flags().GetBool("exit-node")
	useShield, _ := cmd.Flags().GetBool("shield")

	// Set defaults
	if hostname == "" {
		hostname = "eos-node"
	}
	if vaultPath == "" {
		vaultPath = "tailscale"
	}

	// INTERVENE - Build configuration
	config := &network.TailscaleConfig{
		Hostname:         hostname,
		AdvertiseRoutes:  advertiseRoutes,
		AcceptRoutes:     acceptRoutes,
		Tags:             tags,
		TerraformDir:     terraformDir,
		VaultPath:        vaultPath,
		UseAdvertiseExit: useExitNode,
		UseShield:        useShield,
		Metadata: map[string]string{
			"deployed_by": "eos",
			"component":   "tailscale",
		},
	}

	logger.Info("Tailscale configuration prepared",
		zap.String("hostname", config.Hostname),
		zap.Strings("advertise_routes", config.AdvertiseRoutes),
		zap.String("vault_path", config.VaultPath),
		zap.Bool("use_terraform", terraformDir != ""))

	// EVALUATE - Deploy using the network package
	logger.Info("Deploying Tailscale infrastructure")
	return network.DeployTailscaleInfrastructure(rc, config)
}
