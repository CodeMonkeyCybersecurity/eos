// cmd/delete/k3s.go

package delete

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/k3s"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var DeleteK3sCmd = &cobra.Command{
	Use:          "k3s",
	SilenceUsage: true,
	Short:        "Uninstall K3s from this machine",
	Long: `Detects whether this machine is running a K3s server or agent,
and removes it by running the appropriate uninstall scripts in the correct order.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		if err := k3s.Uninstall(rc); err != nil {
			otelzap.Ctx(rc.Ctx).Error(" Failed to uninstall K3s", zap.Error(err))
			return err
		}
		otelzap.Ctx(rc.Ctx).Info(" K3s uninstallation completed.")
		return nil
	}),
}


func init() {
	DeleteCmd.AddCommand(DeleteK3sCmd)
}
