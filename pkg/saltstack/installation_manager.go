package saltstack

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallationManager handles multiple installation strategies with fallbacks
type InstallationManager struct {
	strategies []InstallationStrategy
}

// NewInstallationManager creates a new installation manager with default strategies
func NewInstallationManager(rc *eos_io.RuntimeContext) *InstallationManager {
	return &InstallationManager{
		strategies: []InstallationStrategy{
			NewBootstrapInstaller(),         // Primary method (most reliable)
			NewVersionAwareInstaller(rc),    // Legacy repository method (fallback)
			NewDirectDownloadInstaller(),    // Direct package download
			NewManualInstaller(),            // Manual guidance (last resort)
		},
	}
}

// Install attempts installation using multiple strategies until one succeeds
func (m *InstallationManager) Install(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Salt installation with fallback strategies",
		zap.Int("available_strategies", len(m.strategies)))

	var lastErr error

	for i, strategy := range m.strategies {
		logger.Info("Attempting installation strategy",
			zap.Int("attempt", i+1),
			zap.String("method", strategy.Name()),
			zap.Int("total_strategies", len(m.strategies)))

		// Try installation
		if err := strategy.Install(rc, config.Version, config); err != nil {
			logger.Warn("Installation strategy failed",
				zap.String("method", strategy.Name()),
				zap.Error(err))
			lastErr = err
			continue
		}

		// Verify installation worked
		if err := strategy.Verify(rc); err != nil {
			logger.Warn("Installation verification failed",
				zap.String("method", strategy.Name()),
				zap.Error(err))
			lastErr = err
			continue
		}

		logger.Info("Successfully installed Salt",
			zap.String("method", strategy.Name()))
		return nil
	}

	return fmt.Errorf("all installation methods failed, last error: %w", lastErr)
}

// DirectDownloadInstaller provides direct package download as fallback
type DirectDownloadInstaller struct {
	installer *Installer
}

// NewDirectDownloadInstaller creates a direct download installer
func NewDirectDownloadInstaller() *DirectDownloadInstaller {
	return &DirectDownloadInstaller{
		installer: NewInstaller(),
	}
}

// Name returns the name of this installation strategy
func (d *DirectDownloadInstaller) Name() string {
	return "Direct Package Download"
}

// Install attempts to install Salt by downloading packages directly
func (d *DirectDownloadInstaller) Install(rc *eos_io.RuntimeContext, version string, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Attempting direct package download installation")

	// Use the existing installer which tries repository method
	return d.installer.Install(rc, config)
}

// Verify verifies the direct download installation
func (d *DirectDownloadInstaller) Verify(rc *eos_io.RuntimeContext) error {
	return d.installer.Verify(rc)
}

// ManualInstaller provides manual installation guidance
type ManualInstaller struct{}

// NewManualInstaller creates a manual installer
func NewManualInstaller() *ManualInstaller {
	return &ManualInstaller{}
}

// Name returns the name of this installation strategy
func (m *ManualInstaller) Name() string {
	return "Manual Installation Guide"
}

// Install provides manual installation instructions
func (m *ManualInstaller) Install(rc *eos_io.RuntimeContext, version string, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("All automated installation methods failed")
	logger.Info("Manual installation instructions:")
	logger.Info("")
	logger.Info("1. Download Salt bootstrap script manually:")
	logger.Info("   curl -o salt-bootstrap.sh https://bootstrap.saltstack.com")
	logger.Info("")
	logger.Info("2. Make it executable:")
	logger.Info("   chmod +x salt-bootstrap.sh")
	logger.Info("")
	logger.Info("3. Run the bootstrap script:")
	if version != "" && version != "latest" {
		logger.Info(fmt.Sprintf("   sudo sh salt-bootstrap.sh -X -N git %s", version))
	} else {
		logger.Info("   sudo sh salt-bootstrap.sh -X -N")
	}
	logger.Info("")
	logger.Info("4. Configure for masterless mode:")
	logger.Info("   sudo mkdir -p /srv/salt /srv/pillar")
	logger.Info("   sudo tee /etc/salt/minion > /dev/null <<EOF")
	logger.Info("file_client: local")
	logger.Info("master_type: disable")
	logger.Info("file_roots:")
	logger.Info("  base:")
	logger.Info("    - /srv/salt")
	logger.Info("pillar_roots:")
	logger.Info("  base:")
	logger.Info("    - /srv/pillar")
	logger.Info("log_level: warning")
	logger.Info("EOF")
	logger.Info("")
	logger.Info("5. Test the installation:")
	logger.Info("   salt-call --local test.ping")
	logger.Info("")
	logger.Info("After manual installation, run 'eos create saltstack --skip-test' to continue")

	// Return an error to indicate manual intervention is needed
	return fmt.Errorf("manual installation required - please follow the instructions above")
}

// Verify checks if manual installation was completed
func (m *ManualInstaller) Verify(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Try to verify if Salt was manually installed
	verifier := NewVerifier()
	if err := verifier.Verify(rc); err != nil {
		logger.Warn("Manual installation not detected or incomplete")
		return fmt.Errorf("manual installation verification failed: %w", err)
	}

	logger.Info("Manual installation appears to be successful")
	return nil
}

// InstallWithStrategy allows forcing a specific installation strategy
func (m *InstallationManager) InstallWithStrategy(rc *eos_io.RuntimeContext, strategyName string, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	for _, strategy := range m.strategies {
		if strategy.Name() == strategyName {
			logger.Info("Using forced installation strategy",
				zap.String("strategy", strategyName))

			if err := strategy.Install(rc, config.Version, config); err != nil {
				return fmt.Errorf("forced strategy %s failed: %w", strategyName, err)
			}

			return strategy.Verify(rc)
		}
	}

	return fmt.Errorf("unknown installation strategy: %s", strategyName)
}

// ListStrategies returns available installation strategies
func (m *InstallationManager) ListStrategies() []string {
	strategies := make([]string, len(m.strategies))
	for i, strategy := range m.strategies {
		strategies[i] = strategy.Name()
	}
	return strategies
}

// PrintSuccessMessage displays success information and next steps
func PrintSuccessMessage(rc *eos_io.RuntimeContext, config *Config) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Salt installation completed successfully!")

	if !config.MasterMode {
		logger.Info("Salt is configured for masterless operation")
		logger.Info("Next steps:")
		logger.Info("1. Create your states in /srv/salt/")
		logger.Info("2. Test with: salt-call --local state.apply")
		logger.Info("3. View available modules: salt-call --local sys.doc")
		logger.Info("4. Apply the test state: salt-call --local state.apply eos.test")
	} else {
		logger.Info("Salt is configured for master-minion operation")
		logger.Info("Additional configuration may be required for your specific setup")
	}

	logger.Info("Other Eos commands can now use Salt for configuration management")
	logger.Info("State files should be placed in /srv/salt/eos/ for Eos-managed states")
}