package list

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/python"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var installCmd = &cobra.Command{
	Use:   "preflight-install",
	Short: "Install Python dependencies required by Delphi services",
	Long: `Install all Python packages required by the Delphi security monitoring services.

This command installs the following dependencies:
- psycopg2-binary (PostgreSQL adapter)
- python-dotenv (Environment variable management)
- requests (HTTP requests library)
- pytz (Timezone handling)
- ipwhois (IP WHOIS lookup functionality)
- pyyaml (YAML parsing for configuration)
- sdnotify (Systemd watchdog integration)
- tabulate (Table formatting for parser-monitor)

The installation method varies by operating system:
- Ubuntu/Debian: Uses apt to install system packages
- Other Linux: Uses pip3 with --break-system-packages if needed
- macOS: Uses pip3 directly

Requires sudo privileges for system-wide installation.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("🐍 Installing Python dependencies for Delphi services")

		// Check if we have sudo privileges
		if !eos_unix.CanInteractiveSudo() {
			logger.Error(" Sudo privileges required for Python package installation")
			return nil
		}

		// Install Python packages
		return python.InstallPackages(rc)
	}),
}

func init() {
	ListCmd.AddCommand(installCmd)
}

// Helper functions have been migrated to:
// - pkg/python/packages.go (package definitions and verification)
// - pkg/python/install.go (installation logic)
// - pkg/platform/ubuntu_detector.go (IsDebianBased - already existed)