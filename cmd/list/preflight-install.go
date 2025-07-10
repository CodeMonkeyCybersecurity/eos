package list

import (
	"os"
	"os/exec"
	"runtime"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
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

		// Detect OS and use appropriate installation method
		os := runtime.GOOS
		logger.Info(" Detected operating system", zap.String("os", os))

		// Check Python version
		pythonCmd := exec.Command("python3", "--version")
		pythonOutput, err := pythonCmd.Output()
		if err != nil {
			logger.Error(" Python 3 not found", zap.Error(err))
			return err
		}
		logger.Info("🐍 Python version", zap.String("version", strings.TrimSpace(string(pythonOutput))))

		// Install based on OS
		switch os {
		case "linux":
			return installLinuxPackages(logger)
		case "darwin":
			return installMacOSPackages(logger)
		default:
			logger.Warn("Unsupported OS, attempting pip3 installation", zap.String("os", os))
			return installWithPip3(logger, false)
		}

	}),
}
// TODO
// installLinuxPackages installs Python packages on Linux systems
// TODO: Move to pkg/python or pkg/system/packages
func installLinuxPackages(logger otelzap.LoggerWithCtx) error {
	// Check if this is a Debian/Ubuntu system
	if isDebianBased() {
		logger.Info("🐧 Detected Debian/Ubuntu system, using apt package manager")
		return installDebianPackages(logger)
	}

	logger.Info("🐧 Non-Debian Linux system, attempting pip3 with fallback options")
	return installWithPip3(logger, true)
}
// TODO
// installDebianPackages installs Python packages using apt on Debian/Ubuntu
func installDebianPackages(logger otelzap.LoggerWithCtx) error {
	// Map pip package names to Debian package names
	debianPackages := []string{
		"python3-psycopg2", // psycopg2-binary -> python3-psycopg2
		"python3-dotenv",   // python-dotenv -> python3-dotenv
		"python3-requests", // requests -> python3-requests
		"python3-tz",       // pytz -> python3-tz
		"python3-yaml",     // pyyaml -> python3-yaml
		"python3-sdnotify", // sdnotify -> python3-sdnotify (for systemd watchdog)
		"python3-tabulate", // tabulate -> python3-tabulate (for parser-monitor)
		// Note: ipwhois is not available as a Debian package, will install via pip3
	}

	logger.Info(" Installing Debian packages",
		zap.Strings("packages", debianPackages),
		zap.Int("count", len(debianPackages)))

	// Update apt cache first
	logger.Info(" Updating apt package cache")
	updateCmd := exec.Command("sudo", "apt", "update")
	updateCmd.Stdout = os.Stdout
	updateCmd.Stderr = os.Stderr
	if err := updateCmd.Run(); err != nil {
		logger.Warn("apt update failed, continuing anyway", zap.Error(err))
	}

	// Install packages
	installArgs := append([]string{"apt", "install", "-y"}, debianPackages...)
	logger.Info(" Installing packages with apt",
		zap.String("command", "sudo"),
		zap.Strings("args", installArgs))

	installCmd := exec.Command("sudo", installArgs...)
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	installCmd.Stdin = os.Stdin

	if err := installCmd.Run(); err != nil {
		logger.Error(" apt package installation failed", zap.Error(err))
		return err
	}

	logger.Info(" Debian packages installed successfully")

	// Install packages not available as Debian packages separately with pip3
	pipPackages := []string{"ipwhois"}
	logger.Info(" Installing additional Python packages with pip3",
		zap.Strings("packages", pipPackages))

	pipCmd := exec.Command("sudo", append([]string{"pip3", "install", "--break-system-packages"}, pipPackages...)...)
	pipCmd.Stdout = os.Stdout
	pipCmd.Stderr = os.Stderr
	if err := pipCmd.Run(); err != nil {
		logger.Warn("Failed to install some pip3 packages",
			zap.Error(err),
			zap.Strings("packages", pipPackages))
	} else {
		logger.Info(" Additional pip3 packages installed successfully")
	}

	return verifyAllPackages(logger)
}
// TODO
// installMacOSPackages installs Python packages on macOS
func installMacOSPackages(logger otelzap.LoggerWithCtx) error {
	logger.Info("🍎 Detected macOS, using pip3 directly")
	return installWithPip3(logger, false)
}
// TODO
// installWithPip3 installs packages using pip3 with optional system package breaking
func installWithPip3(logger otelzap.LoggerWithCtx, useBreakSystemPackages bool) error {
	packages := []string{
		"psycopg2-binary",
		"python-dotenv",
		"requests",
		"pytz",
		"ipwhois",
		"pyyaml",
		"sdnotify",
		"tabulate",
	}

	logger.Info(" Installing Python packages with pip3",
		zap.Strings("packages", packages),
		zap.Int("count", len(packages)),
		zap.Bool("break_system_packages", useBreakSystemPackages))

	// Check if pip3 is available
	pip3Path, err := exec.LookPath("pip3")
	if err != nil {
		logger.Error(" pip3 not found", zap.Error(err))
		return err
	}
	logger.Info(" Found pip3", zap.String("path", pip3Path))

	// Build install command
	var installArgs []string
	if useBreakSystemPackages {
		installArgs = append([]string{"pip3", "install", "--break-system-packages", "--upgrade"}, packages...)
	} else {
		installArgs = append([]string{"pip3", "install", "--upgrade"}, packages...)
	}

	logger.Info(" Executing pip install command",
		zap.String("command", "sudo"),
		zap.Strings("args", installArgs))

	installCmd := exec.Command("sudo", installArgs...)
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	installCmd.Stdin = os.Stdin

	if err := installCmd.Run(); err != nil {
		logger.Error(" pip3 installation failed",
			zap.Error(err),
			zap.Strings("packages", packages))
		return err
	}

	logger.Info(" pip3 packages installed successfully")
	return verifyAllPackages(logger)
}
// TODO
// isDebianBased checks if the current system is Debian/Ubuntu based
// TODO: Move to pkg/system/os or pkg/platform
func isDebianBased() bool {
	// Check for /etc/debian_version
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return true
	}

	// Check for apt command
	if _, err := exec.LookPath("apt"); err == nil {
		return true
	}

	return false
}
// TODO
// verifyAllPackages verifies that all required packages can be imported
// TODO: Move to pkg/python or pkg/system/packages
func verifyAllPackages(logger otelzap.LoggerWithCtx) error {
	logger.Info(" Verifying package installation")

	packages := map[string]string{
		"psycopg2-binary": "psycopg2",
		"python-dotenv":   "dotenv",
		"requests":        "requests",
		"pytz":            "pytz",
		"ipwhois":         "ipwhois",
		"pyyaml":          "yaml",
		"sdnotify":        "sdnotify",
		"tabulate":        "tabulate",
	}

	var failedPackages []string
	var successPackages []string

	for pkg, importName := range packages {
		verifyCmd := exec.Command("python3", "-c", "import "+importName)
		if err := verifyCmd.Run(); err != nil {
			logger.Warn("Package verification failed",
				zap.String("package", pkg),
				zap.String("import_name", importName),
				zap.Error(err))
			failedPackages = append(failedPackages, pkg)
		} else {
			logger.Info(" Package verified",
				zap.String("package", pkg),
				zap.String("import_name", importName))
			successPackages = append(successPackages, pkg)
		}
	}

	// Log summary
	logger.Info(" Package verification summary",
		zap.Int("total", len(packages)),
		zap.Int("successful", len(successPackages)),
		zap.Int("failed", len(failedPackages)))

	if len(failedPackages) > 0 {
		logger.Warn("Some packages failed verification",
			zap.Strings("failed_packages", failedPackages))
	}

	// Show next steps
	logger.Info(" Delphi Python dependencies installation complete")
	logger.Info(" Next steps:")
	logger.Info("   1. Ensure PostgreSQL is installed and running")
	logger.Info("   2. Configure .env file at /opt/stackstorm/packs/delphi/.env")
	logger.Info("   3. Deploy Delphi services: eos create delphi")
	logger.Info("   4. Start services: eos delphi services start --all")

	return nil
}

func init() {
	ListCmd.AddCommand(installCmd)
}
