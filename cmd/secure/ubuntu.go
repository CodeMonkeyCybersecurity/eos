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
	Short: "Harden Ubuntu system with security tools and configurations",
	Long: `Install and configure essential security tools for Ubuntu including:
- auditd for system auditing
- osquery for OS instrumentation  
- AIDE for file integrity monitoring
- Lynis for security auditing
- fail2ban for brute force protection
- Automatic security updates
- Kernel hardening and sysctl settings
- Multi-Factor Authentication (MFA) for sudo/root access`,
	RunE: eos.WrapExtended(7*time.Minute, func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("🛡️ Starting Ubuntu security hardening with extended timeout",
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

		// Handle MFA-only configuration
		if mfaOnly {
			if disableMFA {
				logger.Info("Disabling MFA for sudo/root access")
				return ubuntu.DisableMFA(rc)
			} else {
				logger.Info("Configuring MFA for sudo/root access")
				return ubuntu.ConfigureMFA(rc)
			}
		}

		// Run the standard hardening process
		if err := ubuntu.SecureUbuntu(rc, enableMFA, disableMFA); err != nil {
			logger.Error("Failed to secure Ubuntu", zap.Error(err))
			return fmt.Errorf("secure ubuntu: %w", err)
		}

		logger.Info("Ubuntu security hardening completed successfully")
		return nil
	}),
}

func init() {
	SecureCmd.AddCommand(ubuntuCmd)
	ubuntuCmd.Flags().Bool("enable-mfa", false, "Enable Multi-Factor Authentication for sudo/root access")
	ubuntuCmd.Flags().Bool("disable-mfa", false, "Disable Multi-Factor Authentication for sudo/root access")
	ubuntuCmd.Flags().Bool("mfa-only", false, "Only configure MFA settings without running full hardening")
	ubuntuCmd.MarkFlagsMutuallyExclusive("enable-mfa", "disable-mfa")
}
