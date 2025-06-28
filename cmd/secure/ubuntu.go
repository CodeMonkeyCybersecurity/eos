package secure

import (
	"fmt"
	"os"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ubuntu"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var ubuntuCmd = &cobra.Command{
	Use:   "ubuntu",
	Short: "Comprehensive Ubuntu security hardening with simple MFA setup",
	Long: `Comprehensive security hardening for Ubuntu 24.04 LTS servers with simple
Multi-Factor Authentication (MFA) setup for the root user.

SECURITY TOOLS INSTALLED:
• auditd - Comprehensive system auditing
• osquery - OS instrumentation and monitoring  
• AIDE - File integrity monitoring
• Lynis - Security vulnerability scanning
• fail2ban - Brute force attack protection
• UFW firewall - Network security
• SSH hardening - Secure remote access
• Kernel hardening - System-level security
• Automatic security updates

MFA IMPLEMENTATION:
• Installs Google Authenticator package
• Runs interactive google-authenticator setup for root user
• User guided through QR code scanning and backup code generation
• Simple, straightforward MFA configuration
• Other users can run 'google-authenticator' manually to set up MFA

USAGE EXAMPLES:
• sudo eos secure ubuntu                    # Full hardening + root MFA setup (recommended)
• sudo eos secure ubuntu --enable-mfa       # Same as above (MFA enabled by default)
• sudo eos secure ubuntu --mfa-only         # Only configure MFA, skip other hardening
• sudo eos secure ubuntu --no-mfa           # Skip MFA entirely (dev/test only)

For detailed documentation: /docs/commands/secure-ubuntu.md`,
	RunE: eos.WrapExtended(7*time.Minute, func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Starting Ubuntu security hardening with extended timeout",
			zap.Duration("timeout", 7*time.Minute),
			zap.String("reason", "AIDE installation and security tools require extended time"))

		// Check if running as root
		if os.Geteuid() != 0 {
			return fmt.Errorf("this command must be run as root")
		}

		// Get flags
		enableMFA, _ := cmd.Flags().GetBool("enable-mfa")
		disableMFA, _ := cmd.Flags().GetBool("disable-mfa")
		mfaOnly, _ := cmd.Flags().GetBool("mfa-only")
		noMFA, _ := cmd.Flags().GetBool("no-mfa")
		enforceMFA, _ := cmd.Flags().GetBool("enforce-mfa")

		// Handle MFA-only configuration
		if mfaOnly {
			if disableMFA {
				logger.Info(" MFA disable not implemented in simple mode")
				return fmt.Errorf("MFA disable not available - use --no-mfa for new installations")
			} else {
				logger.Info(" Configuring simple MFA for root user only")
				return ubuntu.ConfigureSimpleMFA(rc)
			}
		}

		// Determine MFA mode for full hardening
		var mfaMode string
		if noMFA {
			mfaMode = "disabled"
			logger.Warn("  MFA disabled - this reduces security significantly")
		} else if enforceMFA || (!enableMFA && !disableMFA) {
			// Default to enforced MFA
			mfaMode = "enforced"
			logger.Info(" MFA will be configured and enforced (default security mode)")
		} else if enableMFA {
			mfaMode = "standard"
			logger.Info(" Standard MFA will be configured")
		} else {
			mfaMode = "disabled"
		}

		// Run the enhanced hardening process
		if err := ubuntu.SecureUbuntuEnhanced(rc, mfaMode); err != nil {
			logger.Error("Failed to secure Ubuntu", zap.Error(err))
			return fmt.Errorf("secure ubuntu: %w", err)
		}

		logger.Info("Ubuntu security hardening completed successfully")
		return nil
	}),
}

func init() {
	SecureCmd.AddCommand(ubuntuCmd)

	// MFA Configuration Flags
	ubuntuCmd.Flags().Bool("enforce-mfa", false, "Strict MFA: require password + MFA token for all sudo access (default)")
	ubuntuCmd.Flags().Bool("enable-mfa", false, "Graceful MFA: allow password fallback during initial setup period")
	ubuntuCmd.Flags().Bool("disable-mfa", false, "Disable existing MFA enforcement (removes MFA requirement)")
	ubuntuCmd.Flags().Bool("no-mfa", false, "Skip MFA configuration entirely (development/testing only)")
	ubuntuCmd.Flags().Bool("mfa-only", false, "Configure MFA only, skip other security hardening")

	// Mark mutually exclusive flags
	ubuntuCmd.MarkFlagsMutuallyExclusive("enforce-mfa", "enable-mfa", "disable-mfa", "no-mfa")
}
