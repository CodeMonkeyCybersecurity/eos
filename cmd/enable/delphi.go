/* cmd/enable/delphi.go */

package enable

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var EnableDelphiCmd = &cobra.Command{
	Use:   "delphi",
	Short: "Enable services and firewall rules for Delphi (Wazuh)",
	Long: `Starts core Wazuh services and opens required ports in the firewall.
This includes 443, 1514, 1515, and 55000.`,
	Aliases: []string{"wazuh"},

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		otelzap.Ctx(rc.Ctx).Info(" Enabling Delphi firewall rules...")

		if err := platform.AllowPorts(rc, delphi.DefaultPorts); err != nil {
			otelzap.Ctx(rc.Ctx).Error(" Firewall configuration failed", zap.Error(err))
			return err
		}

		otelzap.Ctx(rc.Ctx).Info(" Delphi firewall configuration complete.")
		return nil
	}),
}

func init() {
	EnableCmd.AddCommand(EnableDelphiCmd)
}
