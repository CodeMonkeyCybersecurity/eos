package bootstrap

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// BootstrapSalt installs and configures SaltStack from scratch
func BootstrapSalt(rc *eos_io.RuntimeContext, config *SaltConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check if Salt is already installed
	logger.Info("Assessing Salt installation status")
	
	// Use the existing saltstack package which has all the proper checks
	saltConfig := &saltstack.Config{
		MasterMode:   config.MasterMode,
		Version:      config.Version,
		LogLevel:     "info",
		SkipTest:     false,
		ForceVersion: false,
	}
	
	// INTERVENE - Install Salt using the existing implementation
	logger.Info("Installing SaltStack using existing saltstack package")
	
	if err := saltstack.Install(rc, saltConfig); err != nil {
		return err
	}
	
	// EVALUATE - The saltstack.Install already includes verification
	logger.Info("Salt bootstrap completed successfully")
	
	return nil
}