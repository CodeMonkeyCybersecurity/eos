package ubuntu

import (
	"fmt"
	"os"
	"strings"

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

	// Configure PAM to actually enforce MFA
	logger.Info(" Configuring PAM to enforce MFA for sudo and su")
	if err := configurePAMForMFA(rc); err != nil {
		return fmt.Errorf("configure PAM for MFA: %w", err)
	}

	logger.Info(" ")
	logger.Info(" MFA configuration completed successfully")
	logger.Info(" The root account now has MFA configured and enforced")
	logger.Info(" ")
	logger.Info(" NEXT STEPS:")
	logger.Info("   • Save the emergency backup codes in a secure location")
	logger.Info("   • Note the secret key for backup purposes")
	logger.Info("   • Test sudo/su in a NEW terminal before closing this one")
	logger.Info("   • You will now be prompted for password + MFA token")
	logger.Info(" ")

	return nil
}

// configurePAMForMFA adds minimal PAM configuration to enforce MFA
func configurePAMForMFA(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Configure PAM for sudo
	if err := addMFAToPAMFile("/etc/pam.d/sudo"); err != nil {
		return fmt.Errorf("configure sudo PAM: %w", err)
	}
	logger.Info(" Added MFA requirement to sudo")

	// Configure PAM for su
	if err := addMFAToPAMFile("/etc/pam.d/su"); err != nil {
		return fmt.Errorf("configure su PAM: %w", err)
	}
	logger.Info(" Added MFA requirement to su")

	return nil
}

// addMFAToPAMFile adds the MFA requirement to a PAM configuration file
func addMFAToPAMFile(filePath string) error {
	// Read existing PAM file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read PAM file %s: %w", filePath, err)
	}

	// Check if MFA is already configured
	if strings.Contains(string(content), "pam_google_authenticator.so") {
		return nil // Already configured
	}

	// Create backup
	backupPath := filePath + ".backup-before-mfa"
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return fmt.Errorf("create backup of %s: %w", filePath, err)
	}

	// Add MFA line after the first auth line
	lines := strings.Split(string(content), "\n")
	var newLines []string
	mfaAdded := false

	for _, line := range lines {
		newLines = append(newLines, line)
		// Add MFA requirement after the first auth line
		if !mfaAdded && strings.HasPrefix(strings.TrimSpace(line), "auth") {
			newLines = append(newLines, "auth required pam_google_authenticator.so")
			mfaAdded = true
		}
	}

	// If no auth line was found, add it at the beginning
	if !mfaAdded {
		newLines = append([]string{"auth required pam_google_authenticator.so"}, newLines...)
	}

	// Write updated configuration
	newContent := strings.Join(newLines, "\n")
	if err := os.WriteFile(filePath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("write updated PAM file %s: %w", filePath, err)
	}

	return nil
}