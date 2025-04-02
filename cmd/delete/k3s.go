// cmd/delete/k3s.go
package delete

import (
	"fmt"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var DeleteK3sCmd = &cobra.Command{
	Use:   "k3s",
	Short: "Uninstall K3s from this machine",
	Long: `Detects whether this machine is running a K3s server or agent,
and removes it by running the appropriate uninstall scripts in the correct order.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := uninstallK3s(); err != nil {
			log.Error("❌ Failed to uninstall K3s", zap.Error(err))
			return err
		}
		log.Info("✅ K3s uninstallation completed.")
		return nil
	},
}

func uninstallK3s() error {
	scripts := map[string]string{
		"server": "/usr/local/bin/k3s-uninstall.sh",
		"agent":  "/usr/local/bin/k3s-agent-uninstall.sh",
		"kill":   "/usr/local/bin/k3s-killall.sh",
	}

	var ranAny bool
	for role, path := range scripts {
		if utils.FileExists(path) {
			log.Info("▶ Detected uninstall script",
				zap.String("role", role),
				zap.String("path", path),
			)

			err := execute.Execute("sudo", path)
			if err != nil {
				log.Error("❌ Script execution failed",
					zap.String("script", filepath.Base(path)),
					zap.Error(err),
				)
				return fmt.Errorf("failed to run %s script: %w", role, err)
			}

			log.Info("✅ Script executed successfully",
				zap.String("role", role),
			)
			ranAny = true
		}
	}

	if !ranAny {
		log.Warn("⚠️ No uninstall scripts were found at expected paths")
		return fmt.Errorf("no uninstall scripts found at expected paths")
	}

	return nil
}

func init() {
	DeleteCmd.AddCommand(DeleteK3sCmd)
}
