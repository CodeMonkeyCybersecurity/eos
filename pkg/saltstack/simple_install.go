package saltstack

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Install performs Salt installation using a single, reliable method - the official bootstrap script
// This replaces the complex multi-method approach with one method that actually works
func Install(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Installing Salt using simplified, reliable bootstrap method")

	// Use only the bootstrap method - it's the most reliable when using the correct URL
	installer := NewSimpleBootstrapInstaller(config)

	// Simple flow: Install -> done
	// All configuration and verification is handled within the installer
	if err := installer.Install(rc); err != nil {
		logger.Error("Salt installation failed", zap.Error(err))
		return err
	}

	logger.Info("Salt installation completed successfully!")
	logger.Info("Salt is now ready for use by other Eos commands")

	if !config.MasterMode {
		logger.Info("Salt is configured for masterless operation")
		logger.Info("Test with: salt-call --local test.ping")
		logger.Info("Apply states with: salt-call --local state.apply eos.test")
	}

	return nil
}
