/* cmd/enable/delphi.go */

package enable

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var EnableDelphiCmd = &cobra.Command{
	Use:   "delphi",
	Short: "Enable services and firewall rules for Delphi (Wazuh)",
	Long: `Starts core Wazuh services and opens required ports in the firewall.
This includes 443, 1514, 1515, and 55000.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {

		log.Info("🔐 Enabling Delphi firewall rules...")

		if err := platform.AllowPorts(log, delphi.DefaultPorts); err != nil {
			log.Error("❌ Firewall configuration failed", zap.Error(err))
			return err
		}

		log.Info("✅ Delphi firewall configuration complete.")
		return nil
	}),
}

func init() {
	EnableCmd.AddCommand(EnableDelphiCmd)
}
