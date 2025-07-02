package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/infrastructure/network"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	headscaleServerURL string
	headscaleUsername  string
	headscaleConfigDir string
	headscaleInteractive bool
	headscaleFirewallPorts []string
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
		return runCreateHeadscale(rc, cmd, args)
	}),
}

func runCreateHeadscale(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Headscale installation and configuration")

	// Create configuration
	config := &network.HeadscaleConfig{
		ServerURL:     headscaleServerURL,
		Username:      headscaleUsername,
		ConfigDir:     headscaleConfigDir,
		FirewallPorts: headscaleFirewallPorts,
		Interactive:   headscaleInteractive,
	}

	// Set defaults if not provided
	if len(config.FirewallPorts) == 0 {
		config.FirewallPorts = []string{"80/tcp", "443/tcp", "41641/udp"}
	}
	
	// If no server URL provided and not interactive, prompt for it
	if config.ServerURL == "" && !config.Interactive {
		config.Interactive = true
	}

	// Install Headscale
	if err := network.InstallHeadscale(rc, config); err != nil {
		logger.Error("Headscale installation failed", zap.Error(err))
		return err
	}

	// Display status
	status, err := network.GetHeadscaleStatus(rc)
	if err != nil {
		logger.Warn("Failed to get final status", zap.Error(err))
	} else {
		logger.Info("Headscale installation completed successfully",
			zap.Bool("installed", status.Installed),
			zap.Bool("running", status.Running),
			zap.String("version", status.Version),
			zap.Int("users", len(status.Users)))
	}

	return nil
}

func init() {
	CreateCmd.AddCommand(CreateHeadscaleCmd)

	CreateHeadscaleCmd.Flags().StringVar(&headscaleServerURL, "server-url", "", "Server URL for Headscale (e.g., http://localhost:8080)")
	CreateHeadscaleCmd.Flags().StringVar(&headscaleUsername, "username", "", "Username to create in Headscale")
	CreateHeadscaleCmd.Flags().StringVar(&headscaleConfigDir, "config-dir", "/etc/headscale", "Configuration directory")
	CreateHeadscaleCmd.Flags().BoolVar(&headscaleInteractive, "interactive", true, "Interactive setup mode")
	CreateHeadscaleCmd.Flags().StringSliceVar(&headscaleFirewallPorts, "firewall-ports", []string{"80/tcp", "443/tcp", "41641/udp"}, "Firewall ports to open")
}