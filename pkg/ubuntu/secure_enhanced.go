package ubuntu

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecureUbuntuEnhanced performs comprehensive security hardening with enhanced MFA options
func SecureUbuntuEnhanced(rc *eos_io.RuntimeContext, mfaMode string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Starting Enhanced Ubuntu security hardening",
		zap.String("mfa_mode", mfaMode))

	// Check Ubuntu version
	if err := checkUbuntuVersion(rc); err != nil {
		logger.Warn("Ubuntu version check failed", zap.Error(err))
		// Continue anyway as user might know what they're doing
	}

	// Update system first
	if err := updateSystem(rc); err != nil {
		return fmt.Errorf("update system: %w", err)
	}

	// Install basic required packages
	if err := installBasicPackages(rc); err != nil {
		return fmt.Errorf("install basic packages: %w", err)
	}

	// 1. Configure auditd
	logger.Info(" Installing and configuring auditd")
	if err := configureAuditd(rc); err != nil {
		return fmt.Errorf("configure auditd: %w", err)
	}

	// 2. Install osquery
	logger.Info(" Installing osquery")
	if err := installOsquery(rc); err != nil {
		return fmt.Errorf("install osquery: %w", err)
	}

	// 3. Configure enhanced security monitoring with Osquery and Auditd
	logger.Info(" Configuring enhanced security monitoring")
	if err := configureEnhancedMonitoring(rc); err != nil {
		return fmt.Errorf("configure enhanced monitoring: %w", err)
	}

	// 4. Install Lynis
	logger.Info(" Installing Lynis security auditing tool")
	if err := installLynis(rc); err != nil {
		return fmt.Errorf("install Lynis: %w", err)
	}

	// 5. Install needrestart
	logger.Info(" Installing needrestart")
	if err := installNeedrestart(rc); err != nil {
		return fmt.Errorf("install needrestart: %w", err)
	}

	// 6. Configure fail2ban
	logger.Info(" Installing and configuring fail2ban")
	if err := configureFail2ban(rc); err != nil {
		return fmt.Errorf("configure fail2ban: %w", err)
	}

	// 7. Configure unattended upgrades
	logger.Info(" Configuring automatic security updates")
	if err := configureUnattendedUpgrades(rc); err != nil {
		return fmt.Errorf("configure unattended-upgrades: %w", err)
	}

	// 8. Install restic for backups
	logger.Info(" Installing restic backup solution")
	if err := installRestic(rc); err != nil {
		return fmt.Errorf("install restic: %w", err)
	}

	// 9. Apply system hardening
	logger.Info(" Applying system hardening configurations")
	if err := applySystemHardening(rc); err != nil {
		return fmt.Errorf("apply system hardening: %w", err)
	}

	// 10. Create security report script
	logger.Info(" Creating security report script")
	if err := createSecurityReportScript(rc); err != nil {
		return fmt.Errorf("create security report script: %w", err)
	}

	// 11. Configure simple MFA for root user only
	switch mfaMode {
	case "enforced", "standard":
		logger.Info(" Configuring simple Multi-Factor Authentication for root user")
		if err := ConfigureSimpleMFA(rc); err != nil {
			return fmt.Errorf("configure simple MFA: %w", err)
		}
		logger.Info(" Simple MFA configured successfully for root user")

	case "disabled":
		logger.Warn("  MFA configuration skipped - this reduces security")
		logger.Warn("  Consider enabling MFA later with: eos secure ubuntu --enforce-mfa --mfa-only")

	default:
		return fmt.Errorf("unknown MFA mode: %s", mfaMode)
	}

	// Final security summary
	printSecuritySummary(rc, mfaMode)

	logger.Info(" Enhanced Ubuntu security hardening completed successfully",
		zap.String("mfa_mode", mfaMode),
		zap.String("next_steps", "Run 'security-report' for a comprehensive security overview"))

	return nil
}

// printSecuritySummary displays a comprehensive security status summary
func printSecuritySummary(rc *eos_io.RuntimeContext, mfaMode string) {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println()
	fmt.Println(" UBUNTU SECURITY HARDENING COMPLETED")
	fmt.Println("═══════════════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println(" Security Tools Installed & Configured:")
	fmt.Println("   • auditd - Enhanced system activity monitoring and logging")
	fmt.Println("   • osquery - File integrity monitoring and system instrumentation")
	fmt.Println("   • Lynis - Security auditing and hardening recommendations")
	fmt.Println("   • fail2ban - Brute force attack protection")
	fmt.Println("   • needrestart - Service restart recommendations")
	fmt.Println("   • unattended-upgrades - Automatic security updates")
	fmt.Println("   • restic - Backup solution")
	fmt.Println()

	switch mfaMode {
	case "enforced", "standard":
		fmt.Println(" Multi-Factor Authentication: ENFORCED")
		fmt.Println("   • Google Authenticator configured for root user")
		fmt.Println("   • PAM configured to require password + MFA token")
		fmt.Println("   • sudo and su commands now require MFA")
		fmt.Println("   • Emergency backup codes generated")
		fmt.Println("   • Other users can configure MFA manually with: google-authenticator")

	case "disabled":
		fmt.Println("  Multi-Factor Authentication: DISABLED")
		fmt.Println("   • Consider enabling: eos secure ubuntu --enforce-mfa --mfa-only")
	}

	fmt.Println()
	fmt.Println(" Available Commands:")
	fmt.Println("   • security-report     - Generate comprehensive security report")

	if mfaMode == "enforced" || mfaMode == "standard" {
		fmt.Println("   • google-authenticator - Configure MFA for additional users")
	}

	fmt.Println()
	fmt.Println(" System Hardening Applied:")
	fmt.Println("   • Kernel security parameters optimized")
	fmt.Println("   • Network security settings configured")
	fmt.Println("   • File permissions hardened")
	fmt.Println("   • Security monitoring enabled")
	fmt.Println()

	if mfaMode == "enforced" || mfaMode == "standard" {
		fmt.Println(" IMPORTANT NEXT STEPS:")
		fmt.Println("   1. Save the emergency backup codes in a secure location")
		fmt.Println("   2. Test 'sudo -i' or 'su' in a NEW terminal (should ask for password + MFA token)")
		fmt.Println("   3. Keep this terminal open until you confirm MFA is working")
		fmt.Println("   4. Configure MFA for other users: sudo -u username google-authenticator")
		fmt.Println("   5. Store the MFA secret key securely for backup purposes")
		fmt.Println()
	}

	logger.Info("Security summary displayed to user",
		zap.String("mfa_mode", mfaMode))
}
