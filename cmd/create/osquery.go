// cmd/create/osquery.go

package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/osquery"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var createOsQueryCmd = &cobra.Command{
	Use:   "osquery",
	Short: "Install osquery and configure its APT repository",
	Long:  "Installs osquery on Debian/Ubuntu-based systems by configuring the GPG key and APT repository.",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		if err := platform.RequireLinuxDistro(rc, []string{"debian"}); err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Platform requirement not met", zap.Error(err))
		}

		// Ensure the base platform is Linux
		if platform.GetOSPlatform() != "linux" {
			otelzap.Ctx(rc.Ctx).Fatal("osquery install only supported on Linux")
		}

		// Check distro support
		distro := platform.DetectLinuxDistro(rc)
		otelzap.Ctx(rc.Ctx).Info("Detected Linux distribution", zap.String("distro", distro))

		if distro != "debian" {
			otelzap.Ctx(rc.Ctx).Fatal("Unsupported Linux distribution for osquery install", zap.String("distro", distro))
		}

		// Check architecture
		arch := platform.GetArch()
		otelzap.Ctx(rc.Ctx).Info("Detected architecture", zap.String("arch", arch))

		if arch != "amd64" && arch != "arm64" {
			otelzap.Ctx(rc.Ctx).Fatal("Unsupported architecture", zap.String("arch", arch))
		}

		// Run the installer
		if err := osquery.InstallOsquery(rc, arch); err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to install osquery", zap.Error(err))
		}
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(createOsQueryCmd)
}
