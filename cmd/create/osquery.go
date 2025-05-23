// cmd/create/osquery.go

package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/osquery"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var createOsQueryCmd = &cobra.Command{
	Use:   "osquery",
	Short: "Install osquery and configure its APT repository",
	Long:  "Installs osquery on Debian/Ubuntu-based systems by configuring the GPG key and APT repository.",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {

		if err := platform.RequireLinuxDistro([]string{"debian"}); err != nil {
			zap.L().Fatal("Platform requirement not met", zap.Error(err))
		}

		// Ensure the base platform is Linux
		if platform.GetOSPlatform() != "linux" {
			zap.L().Fatal("osquery install only supported on Linux")
		}

		// Check distro support
		distro := platform.DetectLinuxDistro()
		zap.L().Info("Detected Linux distribution", zap.String("distro", distro))

		if distro != "debian" {
			zap.L().Fatal("Unsupported Linux distribution for osquery install", zap.String("distro", distro))
		}

		// Check architecture
		arch := platform.GetArch()
		zap.L().Info("Detected architecture", zap.String("arch", arch))

		if arch != "amd64" && arch != "arm64" {
			zap.L().Fatal("Unsupported architecture", zap.String("arch", arch))
		}

		// Run the installer
		if err := osquery.InstallOsquery(arch); err != nil {
			zap.L().Fatal("Failed to install osquery", zap.Error(err))
		}
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(createOsQueryCmd)
}
