package ubuntu

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// configureFail2ban installs and configures fail2ban using the enhanced implementation
func configureFail2ban(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Configuring fail2ban with enhanced settings")

	// Use default configuration with sane defaults
	config := DefaultFail2banConfig()
	
	// Call the enhanced implementation
	return ConfigureFail2banEnhanced(rc, config)
}
