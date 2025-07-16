package bootstrap

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/osquery"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// BootstrapOSQuery installs and configures OSQuery for system monitoring
func BootstrapOSQuery(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check if OSQuery is already installed
	logger.Info("Assessing OSQuery installation status")
	
	if osquery.IsOsqueryInstalled(rc) {
		logger.Info("OSQuery is already installed")
		// Verify it's working properly
		if err := osquery.VerifyOsqueryInstallation(rc); err != nil {
			logger.Info("OSQuery installed but not working properly, will reinstall")
		} else {
			logger.Info("OSQuery is installed and working properly")
			return nil
		}
	}
	
	// INTERVENE - Install OSQuery using the existing osquery package
	logger.Info("Installing OSQuery using existing osquery package")
	
	if err := osquery.InstallOsquery(rc); err != nil {
		return err
	}
	
	// EVALUATE - Verify the installation
	logger.Info("Verifying OSQuery installation")
	
	if err := osquery.VerifyOsqueryInstallation(rc); err != nil {
		return err
	}
	
	logger.Info("OSQuery bootstrap completed successfully")
	return nil
}