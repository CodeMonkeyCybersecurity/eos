// cmd/delete/hera.go

package delete

import (
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// deleteHeraCmd represents the "delete hera" command.
var DeleteHeraCmd = &cobra.Command{
	Use:   "hera",
	Short: "Deletes the Hera (Authentik) installation files",
	Long:  `Deletes all files and directories under /opt/hera, but leaves the /opt/hera directory itself.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			otelzap.Ctx(rc.Ctx).Fatal("This command must be run as root or with sudo.")
		}

		targetDir := "/opt/hera"

		otelzap.Ctx(rc.Ctx).Info("Deleting contents of Hera installation directory", zap.String("path", targetDir))

		entries, err := os.ReadDir(targetDir)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to read Hera directory", zap.Error(err))
		}

		for _, entry := range entries {
			fullPath := filepath.Join(targetDir, entry.Name())
			if err := os.RemoveAll(fullPath); err != nil {
				otelzap.Ctx(rc.Ctx).Warn("Failed to delete", zap.String("path", fullPath), zap.Error(err))
			} else {
				otelzap.Ctx(rc.Ctx).Info("Deleted", zap.String("path", fullPath))
			}
		}

		otelzap.Ctx(rc.Ctx).Info("Hera deletion complete. Directory /opt/hera still exists.")
		return nil
	}),
}

func init() {
	DeleteCmd.AddCommand(DeleteHeraCmd)
}
