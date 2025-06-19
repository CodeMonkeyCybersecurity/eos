package ubuntu

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecureUbuntu performs comprehensive security hardening for Ubuntu systems
func SecureUbuntu(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🛡️ Starting Ubuntu security hardening process")

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
	logger.Info("🔍 Installing and configuring auditd")
	if err := configureAuditd(rc); err != nil {
		return fmt.Errorf("configure auditd: %w", err)
	}

	// 2. Install osquery
	logger.Info("🔍 Installing osquery")
	if err := installOsquery(rc); err != nil {
		return fmt.Errorf("install osquery: %w", err)
	}

	// 3. Install and configure AIDE
	logger.Info("🔍 Installing AIDE for file integrity monitoring")
	if err := configureAIDE(rc); err != nil {
		return fmt.Errorf("configure AIDE: %w", err)
	}

	// 4. Install Lynis
	logger.Info("🔍 Installing Lynis security auditing tool")
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
	logger.Info("🔄 Configuring automatic security updates")
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
	logger.Info("📊 Creating security report script")
	if err := createSecurityReportScript(rc); err != nil {
		return fmt.Errorf("create security report script: %w", err)
	}

	logger.Info("✅ Ubuntu security hardening completed successfully",
		zap.String("next_steps", "Run 'security-report' for a security overview"))

	return nil
}

func checkUbuntuVersion(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	content, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return fmt.Errorf("read os-release: %w", err)
	}

	if !strings.Contains(string(content), "Ubuntu 24.04") {
		logger.Warn("This script is designed for Ubuntu 24.04",
			zap.String("current_version", extractVersion(string(content))))
	}

	return nil
}

func extractVersion(osRelease string) string {
	lines := strings.Split(osRelease, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VERSION=") {
			return strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
		}
	}
	return "unknown"
}

func updateSystem(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Updating package lists and upgrading system")

	if err := execute.RunSimple(rc.Ctx, "apt-get", "update"); err != nil {
		return fmt.Errorf("apt-get update: %w", err)
	}

	if err := execute.RunSimple(rc.Ctx, "apt-get", "upgrade", "-y"); err != nil {
		return fmt.Errorf("apt-get upgrade: %w", err)
	}

	return nil
}

func installBasicPackages(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing basic required packages")

	packages := []string{
		"curl",
		"wget",
		"gnupg",
		"lsb-release",
		"software-properties-common",
		"apt-transport-https",
		"ca-certificates",
	}

	args := append([]string{"install", "-y"}, packages...)
	if err := execute.RunSimple(rc.Ctx, "apt-get", args...); err != nil {
		return fmt.Errorf("install basic packages: %w", err)
	}

	return nil
}