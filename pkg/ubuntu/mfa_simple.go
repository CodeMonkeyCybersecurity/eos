package ubuntu

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// ConfigureSimpleMFA installs google-authenticator and runs interactive setup for root user only
func ConfigureSimpleMFA(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Configuring simple MFA for root user only")

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	// Install google-authenticator package
	logger.Info(" Installing Google Authenticator package")
	if err := execute.RunSimple(rc.Ctx, "apt-get", "update"); err != nil {
		return fmt.Errorf("update package lists: %w", err)
	}

	if err := execute.RunSimple(rc.Ctx, "apt-get", "install", "-y", "libpam-google-authenticator"); err != nil {
		return fmt.Errorf("install google-authenticator: %w", err)
	}

	logger.Info(" Google Authenticator package installed successfully")

	// Run interactive google-authenticator command for root
	logger.Info(" ")
	logger.Info(" Starting interactive Google Authenticator setup for root user")
	logger.Info(" Please follow the prompts to configure MFA for the root account")
	logger.Info(" ")

	// Run the interactive google-authenticator command
	// Use execute.Run without Capture=true so it can interact with the terminal
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "google-authenticator",
		Args:    []string{},
	}); err != nil {
		return fmt.Errorf("run interactive google-authenticator: %w", err)
	}

	logger.Info(" ")
	logger.Info(" Google Authenticator setup completed for root user")
	logger.Info(" The root account now has MFA configured")
	logger.Info(" ")
	logger.Info(" NEXT STEPS:")
	logger.Info("   • Save the emergency backup codes in a secure location")
	logger.Info("   • Note the secret key for backup purposes")
	logger.Info("   • Test the configuration by attempting to use sudo")
	logger.Info(" ")

	return nil
}