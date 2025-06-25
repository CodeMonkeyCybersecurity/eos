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
	logger.Info("📊 Installing and configuring auditd")
	if err := configureAuditd(rc); err != nil {
		return fmt.Errorf("configure auditd: %w", err)
	}

	// 2. Install osquery
	logger.Info("🔍 Installing osquery")
	if err := installOsquery(rc); err != nil {
		return fmt.Errorf("install osquery: %w", err)
	}

	// 3. Install and configure AIDE
	logger.Info("🛡️ Installing AIDE for file integrity monitoring")
	if err := configureAIDE(rc); err != nil {
		return fmt.Errorf("configure AIDE: %w", err)
	}

	// 4. Install Lynis
	logger.Info("🔎 Installing Lynis security auditing tool")
	if err := installLynis(rc); err != nil {
		return fmt.Errorf("install Lynis: %w", err)
	}

	// 5. Install needrestart
	logger.Info("🔄 Installing needrestart")
	if err := installNeedrestart(rc); err != nil {
		return fmt.Errorf("install needrestart: %w", err)
	}

	// 6. Configure fail2ban
	logger.Info("🚫 Installing and configuring fail2ban")
	if err := configureFail2ban(rc); err != nil {
		return fmt.Errorf("configure fail2ban: %w", err)
	}

	// 7. Configure unattended upgrades
	logger.Info("⚡ Configuring automatic security updates")
	if err := configureUnattendedUpgrades(rc); err != nil {
		return fmt.Errorf("configure unattended-upgrades: %w", err)
	}

	// 8. Install restic for backups
	logger.Info("💾 Installing restic backup solution")
	if err := installRestic(rc); err != nil {
		return fmt.Errorf("install restic: %w", err)
	}

	// 9. Apply system hardening
	logger.Info("🔒 Applying system hardening configurations")
	if err := applySystemHardening(rc); err != nil {
		return fmt.Errorf("apply system hardening: %w", err)
	}

	// 10. Create security report script
	logger.Info("📋 Creating security report script")
	if err := createSecurityReportScript(rc); err != nil {
		return fmt.Errorf("create security report script: %w", err)
	}

	// 11. Configure MFA based on mode
	switch mfaMode {
	case "enforced":
		logger.Info(" Configuring ENFORCED Multi-Factor Authentication")
		if err := ConfigureEnforcedMFA(rc); err != nil {
			return fmt.Errorf("configure enforced MFA: %w", err)
		}
		logger.Info(" ENFORCED MFA configured successfully")

	case "standard":
		logger.Info(" Configuring standard Multi-Factor Authentication")
		if err := configureMFA(rc); err != nil {
			return fmt.Errorf("configure standard MFA: %w", err)
		}
		logger.Info(" Standard MFA configured successfully")

	case "disabled":
		logger.Warn("⚠️  MFA configuration skipped - this reduces security")
		logger.Warn("⚠️  Consider enabling MFA later with: eos secure ubuntu --enforce-mfa --mfa-only")

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
	fmt.Println("   • auditd - System activity monitoring and logging")
	fmt.Println("   • osquery - Operating system instrumentation framework")
	fmt.Println("   • AIDE - File integrity monitoring")
	fmt.Println("   • Lynis - Security auditing and hardening recommendations")
	fmt.Println("   • fail2ban - Brute force attack protection")
	fmt.Println("   • needrestart - Service restart recommendations")
	fmt.Println("   • unattended-upgrades - Automatic security updates")
	fmt.Println("   • restic - Backup solution")
	fmt.Println()

	switch mfaMode {
	case "enforced":
		fmt.Println(" Multi-Factor Authentication: ENFORCED")
		fmt.Println("   • All sudo operations require MFA")
		fmt.Println("   • Password-only fallback disabled")
		fmt.Println("   • Emergency access: disable-mfa-emergency")
		fmt.Println("   • Status check: mfa-status")
		fmt.Println("   • User setup: setup-mfa")

	case "standard":
		fmt.Println(" Multi-Factor Authentication: ENABLED")
		fmt.Println("   • MFA required for sudo operations")
		fmt.Println("   • Password fallback available")
		fmt.Println("   • User setup: setup-mfa")

	case "disabled":
		fmt.Println("⚠️  Multi-Factor Authentication: DISABLED")
		fmt.Println("   • Consider enabling: eos secure ubuntu --enforce-mfa --mfa-only")
	}

	fmt.Println()
	fmt.Println("📋 Available Commands:")
	fmt.Println("   • security-report     - Generate comprehensive security report")
	fmt.Println("   • mfa-status          - Check MFA configuration status")
	fmt.Println("   • setup-mfa           - Configure MFA for current user")

	if mfaMode == "enforced" {
		fmt.Println("   • enforce-mfa-strict  - Enable strict MFA enforcement")
		fmt.Println("   • disable-mfa-emergency - Emergency MFA disable (admin only)")
	}

	fmt.Println()
	fmt.Println("🔧 System Hardening Applied:")
	fmt.Println("   • Kernel security parameters optimized")
	fmt.Println("   • Network security settings configured")
	fmt.Println("   • File permissions hardened")
	fmt.Println("   • Security monitoring enabled")
	fmt.Println()

	if mfaMode == "enforced" {
		fmt.Println("🚨 IMPORTANT NEXT STEPS:")
		fmt.Println("   1. Ensure all users run 'setup-mfa' to configure their accounts")
		fmt.Println("   2. Test sudo access in a separate terminal before logging out")
		fmt.Println("   3. Store emergency backup codes securely")
		fmt.Println("   4. Run 'mfa-status' to verify configuration")
		fmt.Println()
	}

	logger.Info("Security summary displayed to user",
		zap.String("mfa_mode", mfaMode))
}
