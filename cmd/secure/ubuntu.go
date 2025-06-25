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
	Short: "Harden Ubuntu system with security tools and ENFORCED MFA",
	Long: `Install and configure essential security tools for Ubuntu including:
- auditd for system auditing
- osquery for OS instrumentation  
- AIDE for file integrity monitoring
- Lynis for security auditing
- fail2ban for brute force protection
- Automatic security updates
- Kernel hardening and sysctl settings
- ENFORCED Multi-Factor Authentication (MFA) for sudo/root access (default)

By default, this command will guide you through MFA setup and enforce it.
Use --no-mfa to skip MFA configuration (not recommended for production).`,
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
				logger.Info(" Disabling MFA for sudo/root access")
				return ubuntu.DisableMFA(rc)
			} else if enforceMFA {
				logger.Info(" Configuring ENFORCED MFA for sudo/root access")
				return ubuntu.ConfigureEnforcedMFA(rc)
			} else {
				logger.Info(" Configuring standard MFA for sudo/root access")
				return ubuntu.ConfigureMFA(rc)
			}
		}

		// Determine MFA mode for full hardening
		var mfaMode string
		if noMFA {
			mfaMode = "disabled"
			logger.Warn("⚠️  MFA disabled - this reduces security significantly")
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
	ubuntuCmd.Flags().Bool("enforce-mfa", false, "Enable ENFORCED Multi-Factor Authentication (default if no MFA flags specified)")
	ubuntuCmd.Flags().Bool("enable-mfa", false, "Enable standard Multi-Factor Authentication for sudo/root access")
	ubuntuCmd.Flags().Bool("disable-mfa", false, "Disable Multi-Factor Authentication for sudo/root access")
	ubuntuCmd.Flags().Bool("no-mfa", false, "Skip MFA configuration entirely (not recommended for production)")
	ubuntuCmd.Flags().Bool("mfa-only", false, "Only configure MFA settings without running full hardening")

	// Mark mutually exclusive flags
	ubuntuCmd.MarkFlagsMutuallyExclusive("enforce-mfa", "enable-mfa", "disable-mfa", "no-mfa")
}
