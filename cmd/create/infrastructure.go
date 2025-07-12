// cmd/create/infrastructure.go

package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/infrastructure/deploy"
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
			return deploy.DeployTailscale(rc, cmd)
		case "traefik":
			return deploy.DeployTraefik(rc, cmd)
		case "headscale":
			return deploy.DeployHeadscale(rc, cmd)
		default:
			logger.Error("Unsupported infrastructure service", zap.String("service", serviceName))
			return cmd.Help()
		}
	}),
}

// Helper functions have been migrated to:
// - pkg/infrastructure/deploy/tailscale.go (DeployTailscale)
// - pkg/infrastructure/deploy/traefik.go (DeployTraefik)
// - pkg/infrastructure/deploy/headscale.go (DeployHeadscale)

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
