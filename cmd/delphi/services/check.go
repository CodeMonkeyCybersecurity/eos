package services

import (
	"os/exec"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check Python dependencies required by Delphi services",
	Long: `Check if all Python packages required by the Delphi security monitoring services are installed.

This command verifies the following dependencies:
- psycopg2-binary (PostgreSQL adapter)
- python-dotenv (Environment variable management)
- requests (HTTP requests library)
- pytz (Timezone handling)
- ipwhois (IP WHOIS lookup functionality)
- pyyaml (YAML parsing for configuration)

If any dependencies are missing, use 'eos delphi services install' to install them.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("🔍 Checking Python dependencies for Delphi services")

		// Check Python and pip availability
		pythonCmd := exec.Command("python3", "--version")
		pythonOutput, err := pythonCmd.Output()
		if err != nil {
			logger.Error(" Python 3 not found", zap.Error(err))
			return err
		}

		pythonVersion := strings.TrimSpace(string(pythonOutput))
		logger.Info("🐍 Python version", zap.String("version", pythonVersion))

		pip3Path, err := exec.LookPath("pip3")
		if err != nil {
			logger.Error(" pip3 not found", zap.Error(err))
			return err
		}

		logger.Info(" pip3 available", zap.String("path", pip3Path))

		// Define required packages and their import names
		packages := map[string]string{
			"psycopg2-binary": "psycopg2",
			"python-dotenv":   "dotenv",
			"requests":        "requests",
			"pytz":            "pytz",
			"ipwhois":         "ipwhois",
			"pyyaml":          "yaml",
		}

		logger.Info("🔍 Checking package availability",
			zap.Int("total_packages", len(packages)))

		var missingPackages []string
		var installedPackages []string

		for pkg, importName := range packages {
			// Try to import the package
			importCmd := exec.Command("python3", "-c", "import "+importName)
			if err := importCmd.Run(); err != nil {
				logger.Warn(" Package not available",
					zap.String("package", pkg),
					zap.String("import_name", importName))
				missingPackages = append(missingPackages, pkg)
			} else {
				logger.Info(" Package available",
					zap.String("package", pkg),
					zap.String("import_name", importName))
				installedPackages = append(installedPackages, pkg)
			}
		}

		// Show summary
		logger.Info(" Dependency check summary",
			zap.Int("total", len(packages)),
			zap.Int("installed", len(installedPackages)),
			zap.Int("missing", len(missingPackages)))

		if len(installedPackages) > 0 {
			logger.Info(" Installed packages",
				zap.Strings("packages", installedPackages))
		}

		if len(missingPackages) > 0 {
			logger.Warn("Missing packages",
				zap.Strings("packages", missingPackages))
			logger.Info("💡 To install missing packages, run:")
			logger.Info("   eos delphi services install")

			// Also show manual installation command
			logger.Info("💡 Or install manually with:")
			logger.Info("   sudo pip3 install " + strings.Join(missingPackages, " "))
		} else {
			logger.Info(" All Python dependencies are installed!")
			logger.Info("💡 Next steps:")
			logger.Info("   1. Ensure PostgreSQL is running")
			logger.Info("   2. Configure environment variables")
			logger.Info("   3. Check service status: eos delphi services status --all")
		}

		// Additional system checks
		logger.Info("🔍 Additional system checks")

		// Check PostgreSQL client
		psqlCmd := exec.Command("psql", "--version")
		if psqlOutput, err := psqlCmd.Output(); err != nil {
			logger.Warn("PostgreSQL client (psql) not found",
				zap.Error(err))
		} else {
			logger.Info(" PostgreSQL client available",
				zap.String("version", strings.TrimSpace(string(psqlOutput))))
		}

		// Check if systemctl is available (for service management)
		systemctlCmd := exec.Command("systemctl", "--version")
		if systemctlOutput, err := systemctlCmd.Output(); err != nil {
			logger.Warn("systemctl not found - service management may not work",
				zap.Error(err))
		} else {
			systemctlVersion := strings.Split(string(systemctlOutput), "\n")[0]
			logger.Info(" systemctl available",
				zap.String("version", strings.TrimSpace(systemctlVersion)))
		}

		return nil
	}),
}

func init() {
	ServicesCmd.AddCommand(checkCmd)
}
