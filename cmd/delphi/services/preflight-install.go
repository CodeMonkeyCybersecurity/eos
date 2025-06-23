package services

import (
	"os"
	"os/exec"
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

The installation uses pip3 and requires sudo privileges for system-wide installation.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("🐍 Installing Python dependencies for Delphi services")

		// Check if we have sudo privileges
		if !eos_unix.CanInteractiveSudo() {
			logger.Error("❌ Sudo privileges required for Python package installation")
			return nil
		}

		// Define required Python packages
		packages := []string{
			"psycopg2-binary",  // PostgreSQL adapter (binary version for easier installation)
			"python-dotenv",    // Environment variable management
			"requests",         // HTTP requests library
			"pytz",            // Timezone handling
			"ipwhois",         // IP WHOIS lookup functionality
			"pyyaml",          // YAML parsing for configuration
		}

		logger.Info("📦 Installing Python packages",
			zap.Strings("packages", packages),
			zap.Int("count", len(packages)))

		// Check if pip3 is available
		pip3Path, err := exec.LookPath("pip3")
		if err != nil {
			logger.Error("❌ pip3 not found - Python 3 and pip3 must be installed",
				zap.Error(err))
			return err
		}

		logger.Info("🔍 Found pip3", zap.String("path", pip3Path))

		// Check Python version
		pythonCmd := exec.Command("python3", "--version")
		pythonOutput, err := pythonCmd.Output()
		if err != nil {
			logger.Warn("⚠️ Could not determine Python version", zap.Error(err))
		} else {
			logger.Info("🐍 Python version", zap.String("version", strings.TrimSpace(string(pythonOutput))))
		}

		// Install packages using pip3
		installArgs := append([]string{"pip3", "install", "--upgrade"}, packages...)
		
		logger.Info("🔧 Executing pip install command",
			zap.String("command", "sudo"),
			zap.Strings("args", installArgs))

		installCmd := exec.Command("sudo", installArgs...)
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr
		installCmd.Stdin = os.Stdin

		err = installCmd.Run()
		if err != nil {
			logger.Error("❌ Python package installation failed",
				zap.Error(err),
				zap.Strings("packages", packages))
			return err
		}

		logger.Info("✅ Python dependencies installed successfully",
			zap.Strings("packages", packages),
			zap.Int("count", len(packages)))

		// Verify installation by checking each package
		logger.Info("🔍 Verifying package installation")
		
		for _, pkg := range packages {
			verifyCmd := exec.Command("python3", "-c", "import "+getImportName(pkg))
			if err := verifyCmd.Run(); err != nil {
				logger.Warn("⚠️ Package verification failed",
					zap.String("package", pkg),
					zap.Error(err))
			} else {
				logger.Info("✅ Package verified",
					zap.String("package", pkg))
			}
		}

		logger.Info("🎉 Delphi Python dependencies installation complete")
		logger.Info("💡 Next steps:")
		logger.Info("   1. Ensure PostgreSQL is installed and running")
		logger.Info("   2. Configure .env file at /opt/stackstorm/packs/delphi/.env")
		logger.Info("   3. Deploy Delphi services: eos create delphi")
		logger.Info("   4. Start services: eos delphi services start --all")

		return nil
	}),
}

// getImportName maps package names to their import names for verification
func getImportName(pkg string) string {
	switch pkg {
	case "psycopg2-binary":
		return "psycopg2"
	case "python-dotenv":
		return "dotenv"
	case "pyyaml":
		return "yaml"
	default:
		return pkg
	}
}

func init() {
	ServicesCmd.AddCommand(installCmd)
}