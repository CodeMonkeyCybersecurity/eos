// cmd/delete/k3s.go
package delete

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var DeleteK3sCmd = &cobra.Command{
	Use:          "k3s",
	SilenceUsage: true,
	Short:        "Uninstall K3s from this machine",
	Long: `Detects whether this machine is running a K3s server or agent,
and removes it by running the appropriate uninstall scripts in the correct order.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		if err := uninstallK3s(); err != nil {
			log.Error("❌ Failed to uninstall K3s", zap.Error(err))
			return err
		}
		log.Info("✅ K3s uninstallation completed.")
		return nil
	}),
}

func uninstallK3s() error {
	scripts := map[string]string{
		"server": "/usr/local/bin/k3s-uninstall.sh",
		"agent":  "/usr/local/bin/k3s-agent-uninstall.sh",
		"kill":   "/usr/local/bin/k3s-killall.sh",
	}

	var ranAny bool
	for role, path := range scripts {
		if system.Exists(path) {
			log.Info("▶ Detected uninstall script",
				zap.String("role", role),
				zap.String("path", path),
			)
			err := execute.Execute(path)
			if err != nil {
				log.Error("❌ Script execution failed",
					zap.String("role", role),
					zap.Error(err),
				)
				return fmt.Errorf("failed to run %s script: %w", role, err)
			}
			log.Info("✅ Successfully ran uninstall script",
				zap.String("role", role),
			)
			ranAny = true
		}
	}

	if !ranAny {
		log.Warn("⚠️ No uninstall scripts were found at expected paths. Assuming K3s is not installed.")
		return nil
	}

	return nil
}

func init() {
	DeleteCmd.AddCommand(DeleteK3sCmd)
}
