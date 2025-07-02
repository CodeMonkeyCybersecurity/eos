package read

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/infrastructure/network"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	showHeadscaleStatus bool
)

// ReadTailscaleCmd represents the read tailscale command
var ReadTailscaleCmd = &cobra.Command{
	Use:   "tailscale",
	Short: "Display Tailscale network status and information",
	Long: `Display comprehensive information about the Tailscale network including:
- Network status and backend state
- Self information (hostname, IP, online status)
- Connected peers and their status
- Exit nodes and route advertisements

Examples:
  eos read tailscale                    # Show Tailscale network status
  eos read tailscale --headscale        # Show Headscale server status`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return runReadTailscale(rc, cmd, args)
	}),
}

func runReadTailscale(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if showHeadscaleStatus {
		logger.Info("Checking Headscale status")
		status, err := network.GetHeadscaleStatus(rc)
		if err != nil {
			logger.Error("Failed to get Headscale status", zap.Error(err))
			return err
		}

		logger.Info("=== Headscale Status ===")
		logger.Info("Installed", zap.Bool("installed", status.Installed))
		logger.Info("Running", zap.Bool("running", status.Running))
		logger.Info("Version", zap.String("version", status.Version))
		logger.Info("Config Exists", zap.Bool("config_exists", status.ConfigExists))
		logger.Info("Database Ready", zap.Bool("database_ready", status.DatabaseReady))
		
		if len(status.Users) > 0 {
			logger.Info("Users:")
			for _, user := range status.Users {
				logger.Info("", zap.String("id", user.ID), zap.String("name", user.Name))
			}
		}

		if len(status.PreAuthKeys) > 0 {
			logger.Info("Pre-Auth Keys:")
			for _, key := range status.PreAuthKeys {
				logger.Info("", 
					zap.String("id", key.ID),
					zap.Bool("reusable", key.Reusable),
					zap.String("expiration", key.Expiration),
					zap.Bool("used", key.Used))
			}
		}

		return nil
	}

	// Default: show Tailscale network status
	logger.Info("Displaying Tailscale network status")
	return network.DisplayTailscaleStatus(rc)
}

func init() {
	ReadCmd.AddCommand(ReadTailscaleCmd)

	ReadTailscaleCmd.Flags().BoolVar(&showHeadscaleStatus, "headscale", false, "Show Headscale server status instead of Tailscale network")
}