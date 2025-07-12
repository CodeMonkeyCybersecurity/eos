package python

import (
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Package represents a Python package with its pip name and import name
type Package struct {
	PipName    string
	ImportName string
}

// GetDelphiPackages returns all Python packages required by Delphi services
func GetDelphiPackages() []Package {
	return []Package{
		{PipName: "psycopg2-binary", ImportName: "psycopg2"},
		{PipName: "python-dotenv", ImportName: "dotenv"},
		{PipName: "requests", ImportName: "requests"},
		{PipName: "pytz", ImportName: "pytz"},
		{PipName: "ipwhois", ImportName: "ipwhois"},
		{PipName: "pyyaml", ImportName: "yaml"},
		{PipName: "sdnotify", ImportName: "sdnotify"},
		{PipName: "tabulate", ImportName: "tabulate"},
	}
}

// GetDebianPackageNames returns the Debian package names for Python packages
func GetDebianPackageNames() []string {
	return []string{
		"python3-psycopg2", // psycopg2-binary -> python3-psycopg2
		"python3-dotenv",   // python-dotenv -> python3-dotenv
		"python3-requests", // requests -> python3-requests
		"python3-tz",       // pytz -> python3-tz
		"python3-yaml",     // pyyaml -> python3-yaml
		"python3-sdnotify", // sdnotify -> python3-sdnotify
		"python3-tabulate", // tabulate -> python3-tabulate
		// Note: ipwhois is not available as a Debian package
	}
}

// GetPipOnlyPackages returns packages that must be installed via pip on Debian
func GetPipOnlyPackages() []string {
	return []string{"ipwhois"}
}

// VerifyPackage verifies that a Python package can be imported
// Migrated from cmd/list/preflight-install.go (part of verifyAllPackages)
func VerifyPackage(rc *eos_io.RuntimeContext, pkg Package) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare verification
	logger.Debug("Assessing package verification",
		zap.String("package", pkg.PipName),
		zap.String("import_name", pkg.ImportName))

	// INTERVENE - Try to import the package
	verifyCmd := exec.Command("python3", "-c", "import "+pkg.ImportName)

	// EVALUATE - Check if import succeeded
	if err := verifyCmd.Run(); err != nil {
		logger.Warn("Package verification failed",
			zap.String("package", pkg.PipName),
			zap.String("import_name", pkg.ImportName),
			zap.Error(err))
		return err
	}

	logger.Info("Package verified",
		zap.String("package", pkg.PipName),
		zap.String("import_name", pkg.ImportName))

	return nil
}

// VerifyAllPackages verifies that all required packages can be imported
// Migrated from cmd/list/preflight-install.go verifyAllPackages
func VerifyAllPackages(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Get all packages to verify
	logger.Info("Assessing package verification requirements")

	packages := GetDelphiPackages()

	// INTERVENE - Verify each package
	logger.Info("Verifying package installation",
		zap.Int("total_packages", len(packages)))

	var failedPackages []string
	var successPackages []string

	for _, pkg := range packages {
		if err := VerifyPackage(rc, pkg); err != nil {
			failedPackages = append(failedPackages, pkg.PipName)
		} else {
			successPackages = append(successPackages, pkg.PipName)
		}
	}

	// EVALUATE - Report results
	logger.Info("Package verification summary",
		zap.Int("total", len(packages)),
		zap.Int("successful", len(successPackages)),
		zap.Int("failed", len(failedPackages)))

	if len(failedPackages) > 0 {
		logger.Warn("Some packages failed verification",
			zap.Strings("failed_packages", failedPackages))
	}

	// Show next steps
	logger.Info("Delphi Python dependencies installation complete")
	logger.Info("Next steps:")
	logger.Info("  1. Ensure PostgreSQL is installed and running")
	logger.Info("  2. Configure .env file at /opt/stackstorm/packs/delphi/.env")
	logger.Info("  3. Deploy Delphi services: eos create delphi")
	logger.Info("  4. Start services: eos delphi services start --all")

	return nil
}
