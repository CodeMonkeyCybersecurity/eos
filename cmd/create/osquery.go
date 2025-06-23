// cmd/create/osquery.go

package create

import (
	"fmt"
	"os"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/osquery"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var createOsQueryCmd = &cobra.Command{
	Use:   "osquery",
	Short: "Install osquery endpoint visibility agent",
	Long:  "Installs osquery endpoint visibility agent on supported systems for security monitoring. Supports Linux (Debian/Ubuntu, RHEL/CentOS), macOS, and Windows 10+.",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		start := time.Now()

		// Log user context and command details
		pwd, _ := os.Getwd()
		logger.Info("🔍 Starting osquery installation",
			zap.String("user", os.Getenv("USER")),
			zap.String("pwd", pwd),
			zap.String("command_line", strings.Join(os.Args, " ")),
			zap.String("function", "createOsQueryCmd"))

		// Platform validation with detailed logging
		platformOS := platform.GetOSPlatform()
		supportedPlatforms := []string{"linux", "macos", "windows"}
		logger.Info("📊 Checking platform requirements",
			zap.String("os_platform", platformOS),
			zap.Strings("supported_platforms", supportedPlatforms))

		// Validate platform support
		isSupported := false
		for _, supported := range supportedPlatforms {
			if platformOS == supported {
				isSupported = true
				break
			}
		}

		if !isSupported {
			logger.Error("❌ Platform requirement not met",
				zap.String("platform", platformOS),
				zap.Strings("supported", supportedPlatforms),
				zap.String("troubleshooting", "osquery supports Linux, macOS, and Windows platforms"))
			return fmt.Errorf("unsupported platform: %s (supported: %v)", platformOS, supportedPlatforms)
		}

		// Distribution detection for Linux (informational)
		distro := "unknown"
		if platformOS == "linux" {
			distro = platform.DetectLinuxDistro(rc)
			logger.Info("🐧 Linux distribution detected",
				zap.String("distro", distro),
				zap.String("note", "Will attempt installation with detected distribution"))
		}

		// Architecture validation
		arch := platform.GetArch()
		supportedArchs := []string{"amd64", "arm64"}
		isArchSupported := false
		for _, supported := range supportedArchs {
			if arch == supported {
				isArchSupported = true
				break
			}
		}

		logger.Info("🏗️ System architecture detected",
			zap.String("arch", arch),
			zap.Strings("supported_archs", supportedArchs),
			zap.Bool("is_supported", isArchSupported))

		if !isArchSupported {
			logger.Error("❌ Unsupported architecture",
				zap.String("arch", arch),
				zap.Strings("supported", supportedArchs),
				zap.String("troubleshooting", "osquery only supports 64-bit systems (amd64 and arm64)"))
			return fmt.Errorf("unsupported architecture: %s (supported: %v)", arch, supportedArchs)
		}

		// Check if osquery is already installed
		if osquery.IsOsqueryInstalled(rc) {
			logger.Info("ℹ️ osquery is already installed")
			// Verify the existing installation
			if err := osquery.VerifyOsqueryInstallation(rc); err != nil {
				logger.Warn("⚠️ Existing installation verification failed",
					zap.Error(err),
					zap.String("action", "Proceeding with reinstallation"))
			} else {
				logger.Info("✨ osquery is already installed and verified",
					zap.Duration("total_duration", time.Since(start)))
				return nil
			}
		}

		// Log installation phase start
		logger.Info("🚀 Starting osquery installation process",
			zap.String("platform", platformOS),
			zap.String("distro", distro),
			zap.String("arch", arch))

		// Run the installer with timing
		installStart := time.Now()
		if err := osquery.InstallOsquery(rc); err != nil {
			logger.Error("❌ osquery installation failed",
				zap.Error(err),
				zap.String("distro", distro),
				zap.String("arch", arch),
				zap.Duration("duration", time.Since(installStart)),
				zap.String("troubleshooting", "Check network connectivity, package manager locks, and verify you have sudo/admin privileges"))
			return err
		}

		// Verify installation
		logger.Info("🔍 Verifying osquery installation")
		if err := osquery.VerifyOsqueryInstallation(rc); err != nil {
			logger.Warn("⚠️ Installation verification had warnings",
				zap.Error(err),
				zap.String("note", "osquery is installed but may require manual configuration"))
		}

		// Log successful completion with summary
		paths := osquery.GetOsqueryPaths()
		logger.Info("✨ osquery installation complete",
			zap.Duration("total_duration", time.Since(start)),
			zap.Duration("install_duration", time.Since(installStart)),
			zap.String("config_path", paths.ConfigPath),
			zap.String("service_name", paths.ServiceName),
			zap.String("log_path", paths.LogPath),
			zap.String("platform", platformOS),
			zap.String("distro", distro),
			zap.String("arch", arch))

		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(createOsQueryCmd)
}
