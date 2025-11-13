package update

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
	Short: "Comprehensive Ubuntu security hardening with FIDO2/YubiKey SSH authentication",
	Long: `Comprehensive security hardening for Ubuntu 24.04 LTS servers with FIDO2/YubiKey
hardware authentication for SSH access.

SECURITY TOOLS INSTALLED:
• auditd - Comprehensive system auditing
• osquery - OS instrumentation and monitoring  
• AIDE - File integrity monitoring
• Lynis - Security vulnerability scanning
• fail2ban - Brute force attack protection
• UFW firewall - Network security
• SSH hardening - Secure remote access with FIDO2
• Kernel hardening - System-level security
• Automatic security updates

FIDO2 SSH AUTHENTICATION:
• Configures OpenSSH to require FIDO2 hardware keys (YubiKey)
• Removes password-based authentication
• Provides enrollment tool: eos-enroll-fido2
• Includes recovery procedures and documentation
• Supports multiple hardware keys for redundancy

USAGE EXAMPLES:
• sudo eos update ubuntu                    # Full hardening with FIDO2 SSH
• sudo eos update ubuntu --skip-fido2       # Skip FIDO2 setup (keep existing SSH config)

After setup, users must enroll their FIDO2 keys:
• eos-enroll-fido2                         # Run as regular user to enroll key

For detailed documentation: /etc/ssh/FIDO2_RECOVERY.md`,
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
		skipFIDO2, _ := cmd.Flags().GetBool("skip-fido2")

		// Run the hardening with FIDO2 SSH authentication
		logger.Info("Running Ubuntu hardening with FIDO2 SSH authentication")

		if skipFIDO2 {
			logger.Info("Skipping FIDO2 configuration as requested")
			// Run enhanced hardening without MFA or FIDO2
			if err := ubuntu.SecureUbuntuEnhanced(rc, "disabled"); err != nil {
				logger.Error("Failed to secure Ubuntu", zap.Error(err))
				return fmt.Errorf("system hardening: %w", err)
			}
		} else {
			// Run full hardening with FIDO2
			if err := ubuntu.HardenUbuntuWithFIDO2(rc); err != nil {
				logger.Error("Failed to secure Ubuntu with FIDO2", zap.Error(err))
				return fmt.Errorf("secure ubuntu: %w", err)
			}
		}

		logger.Info("Ubuntu security hardening completed successfully")
		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(ubuntuCmd)

	// FIDO2 Configuration Flag
	ubuntuCmd.Flags().Bool("skip-fido2", false, "Skip FIDO2 SSH configuration (keep existing SSH settings)")
}
