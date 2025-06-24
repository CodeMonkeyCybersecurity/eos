// cmd/delete/k3s.go

package delete

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
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
		if err := uninstallK3s(rc); err != nil {
			otelzap.Ctx(rc.Ctx).Error(" Failed to uninstall K3s", zap.Error(err))
			return err
		}
		otelzap.Ctx(rc.Ctx).Info(" K3s uninstallation completed.")
		return nil
	}),
}

func uninstallK3s(rc *eos_io.RuntimeContext) error {
	scripts := map[string]string{
		"server": "/usr/local/bin/k3s-uninstall.sh",
		"agent":  "/usr/local/bin/k3s-agent-uninstall.sh",
		"kill":   "/usr/local/bin/k3s-killall.sh",
	}

	var ranAny bool
	for role, path := range scripts {
		if eos_unix.Exists(path) {
			otelzap.Ctx(rc.Ctx).Info("▶ Detected uninstall script",
				zap.String("role", role),
				zap.String("path", path),
			)
			err := execute.RunSimple(rc.Ctx, path)
			if err != nil {
				otelzap.Ctx(rc.Ctx).Error(" Script execution failed",
					zap.String("role", role),
					zap.Error(err),
				)
				return fmt.Errorf("failed to run %s script: %w", role, err)
			}
			otelzap.Ctx(rc.Ctx).Info(" Successfully ran uninstall script",
				zap.String("role", role),
			)
			ranAny = true
		}
	}

	if !ranAny {
		otelzap.Ctx(rc.Ctx).Warn("No uninstall scripts were found at expected paths. Assuming K3s is not installed.")
		return nil
	}

	return nil
}

func init() {
	DeleteCmd.AddCommand(DeleteK3sCmd)
}
