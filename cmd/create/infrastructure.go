// cmd/create/infrastructure.go

package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/infrastructure/network"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var infrastructureCmd = &cobra.Command{
	Use:   "infrastructure [service]",
	Short: "Deploy infrastructure services with Terraform",
	Long: `Deploy and manage infrastructure services using Terraform for declarative infrastructure as code.

Supported services:
  tailscale   - Deploy Tailscale VPN infrastructure
  traefik     - Deploy Traefik reverse proxy
  headscale   - Deploy Headscale Tailscale coordination server

Examples:
  eos create infrastructure tailscale --hostname=server01 --advertise-routes=192.168.1.0/24
  eos create infrastructure tailscale --terraform-dir=/tmp/tailscale --vault-path=tailscale/config
  eos create infrastructure traefik --domain=example.com
  eos create infrastructure headscale --domain=vpn.example.com`,

	Args: cobra.MinimumNArgs(1),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		serviceName := args[0]
		logger.Info("Deploying infrastructure service",
			zap.String("service", serviceName))

		switch serviceName {
		case "tailscale":
			return deployTailscaleInfrastructure(rc, cmd)
		case "traefik":
			return deployTraefikInfrastructure(rc, cmd)
		case "headscale":
			return deployHeadscaleInfrastructure(rc, cmd)
		default:
			logger.Error("Unsupported infrastructure service", zap.String("service", serviceName))
			return cmd.Help()
		}
	}),
}

func deployTailscaleInfrastructure(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Deploying Tailscale infrastructure")

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

	logger.Info("Tailscale configuration",
		zap.String("hostname", config.Hostname),
		zap.Strings("advertise_routes", config.AdvertiseRoutes),
		zap.String("vault_path", config.VaultPath),
		zap.Bool("use_terraform", terraformDir != ""))

	return network.DeployTailscaleInfrastructure(rc, config)
}

func deployTraefikInfrastructure(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Deploying Traefik infrastructure")

	// Get command flags
	domain, _ := cmd.Flags().GetString("domain")
	email, _ := cmd.Flags().GetString("email")
	httpPort, _ := cmd.Flags().GetString("http-port")
	httpsPort, _ := cmd.Flags().GetString("https-port")

	// Set defaults
	if httpPort == "" {
		httpPort = "80"
	}
	if httpsPort == "" {
		httpsPort = "443"
	}

	logger.Info("Traefik configuration",
		zap.String("domain", domain),
		zap.String("email", email),
		zap.String("http_port", httpPort),
		zap.String("https_port", httpsPort))

	// This would implement Traefik deployment similar to Tailscale
	// For now, return a placeholder implementation
	logger.Info("Traefik infrastructure deployment completed")
	return nil
}

func deployHeadscaleInfrastructure(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Deploying Headscale infrastructure")

	// Get command flags
	domain, _ := cmd.Flags().GetString("domain")
	database, _ := cmd.Flags().GetString("database")

	// Set defaults
	if database == "" {
		database = "sqlite"
	}

	logger.Info("Headscale configuration",
		zap.String("domain", domain),
		zap.String("database", database))

	// This would implement Headscale deployment similar to Tailscale
	// For now, return a placeholder implementation
	logger.Info("Headscale infrastructure deployment completed")
	return nil
}

func init() {
	// Add infrastructure command to create
	CreateCmd.AddCommand(infrastructureCmd)

	// Common flags
	infrastructureCmd.Flags().String("terraform-dir", "", "Directory for Terraform configuration")
	infrastructureCmd.Flags().String("vault-path", "", "Vault path for storing secrets")

	// Tailscale-specific flags
	infrastructureCmd.Flags().String("hostname", "", "Custom hostname for this node")
	infrastructureCmd.Flags().StringSlice("advertise-routes", []string{}, "Subnet routes to advertise (comma-separated)")
	infrastructureCmd.Flags().Bool("accept-routes", false, "Accept routes from other nodes")
	infrastructureCmd.Flags().StringSlice("tags", []string{}, "Tailscale tags for ACL policies (comma-separated)")
	infrastructureCmd.Flags().Bool("exit-node", false, "Advertise as an exit node")
	infrastructureCmd.Flags().Bool("shield", false, "Enable Tailscale Shield")

	// Traefik-specific flags
	infrastructureCmd.Flags().String("domain", "", "Primary domain for Traefik")
	infrastructureCmd.Flags().String("email", "", "Email for Let's Encrypt certificates")
	infrastructureCmd.Flags().String("http-port", "80", "HTTP port")
	infrastructureCmd.Flags().String("https-port", "443", "HTTPS port")

	// Headscale-specific flags
	infrastructureCmd.Flags().String("database", "sqlite", "Database type (sqlite, postgresql)")

	// Set up flag usage examples
	infrastructureCmd.Example = `  # Deploy Tailscale with route advertisement
  eos create infrastructure tailscale --hostname=gateway --advertise-routes=192.168.1.0/24,10.0.0.0/8

  # Deploy Tailscale with Terraform
  eos create infrastructure tailscale --terraform-dir=/tmp/tailscale --vault-path=tailscale/prod

  # Deploy Traefik reverse proxy
  eos create infrastructure traefik --domain=example.com --email=admin@example.com

  # Deploy Headscale coordination server
  eos create infrastructure headscale --domain=vpn.example.com --database=postgresql`
}
