package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/infrastructure/network"
	"github.com/spf13/cobra"
)

// CreateHeadscaleCmd represents the create headscale command
var CreateHeadscaleCmd = &cobra.Command{
	Use:   "headscale",
	Short: "Install and configure Headscale coordination server",
	Long: `Install and configure Headscale, an open-source coordination server for Tailscale.
Headscale allows you to self-host your own Tailscale coordination server.

This command will:
- Update the system and install dependencies
- Download and install the latest Headscale binary
- Generate configuration files
- Set up the database
- Create and start the systemd service
- Configure firewall rules
- Optionally create users and pre-authentication keys

Examples:
  eos create headscale                                    # Interactive setup
  eos create headscale --server-url http://localhost:8080 # Non-interactive
  eos create headscale --username myuser --interactive    # Specify user interactively`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return network.RunCreateHeadscale(rc, cmd, args)
	}),
}

func init() {
	CreateCmd.AddCommand(CreateHeadscaleCmd)

	CreateHeadscaleCmd.Flags().StringVar(&network.HeadscaleServerURL, "server-url", "", "Server URL for Headscale (e.g., http://localhost:8080)")
	CreateHeadscaleCmd.Flags().StringVar(&network.HeadscaleUsername, "username", "", "Username to create in Headscale")
	CreateHeadscaleCmd.Flags().StringVar(&network.HeadscaleConfigDir, "config-dir", "/etc/headscale", "Configuration directory")
	CreateHeadscaleCmd.Flags().BoolVar(&network.HeadscaleInteractive, "interactive", true, "Interactive setup mode")
	CreateHeadscaleCmd.Flags().StringSliceVar(&network.HeadscaleFirewallPorts, "firewall-ports", []string{"80/tcp", "443/tcp", "41641/udp"}, "Firewall ports to open")
}
