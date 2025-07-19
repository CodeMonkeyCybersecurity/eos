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
	Short:        "Uninstall K3s from this machine (DEPRECATED - use 'nomad' instead)",
	Deprecated:   "K3s support is deprecated. Use 'eos delete nomad' for removing Nomad clusters instead.",
	Long: `DEPRECATED: This command is deprecated and will be removed in a future version.
Use 'eos delete nomad' for removing Nomad clusters instead.

K3s has been replaced with HashiCorp Nomad for simpler container orchestration.

Migration:
  # Instead of: eos delete k3s
  # Use:        eos delete nomad

This command will still work but shows a deprecation warning.`,
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
