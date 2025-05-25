// cmd/delete/hera.go

package delete

import (
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// deleteHeraCmd represents the "delete hera" command.
var DeleteHeraCmd = &cobra.Command{
	Use:   "hera",
	Short: "Deletes the Hera (Authentik) installation files",
	Long:  `Deletes all files and directories under /opt/hera, but leaves the /opt/hera directory itself.`,
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			zap.L().Fatal("This command must be run as root or with sudo.")
		}

		targetDir := "/opt/hera"

		zap.L().Info("Deleting contents of Hera installation directory", zap.String("path", targetDir))

		entries, err := os.ReadDir(targetDir)
		if err != nil {
			zap.L().Fatal("Failed to read Hera directory", zap.Error(err))
		}

		for _, entry := range entries {
			fullPath := filepath.Join(targetDir, entry.Name())
			if err := os.RemoveAll(fullPath); err != nil {
				zap.L().Warn("Failed to delete", zap.String("path", fullPath), zap.Error(err))
			} else {
				zap.L().Info("Deleted", zap.String("path", fullPath))
			}
		}

		zap.L().Info("Hera deletion complete. Directory /opt/hera still exists.")
		return nil
	}),
}

func init() {
	DeleteCmd.AddCommand(DeleteHeraCmd)
}
