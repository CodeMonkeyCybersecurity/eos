package ubuntu

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const auditRules = `# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Monitor unauthorized access attempts to files
-a always,exit -F arch=b64 -S open,openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open,openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Monitor sudo usage
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k sudo_usage

# Monitor changes to system files
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Monitor cron
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron

# Make configuration immutable
-e 2
`

func configureAuditd(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Install auditd
	if err := execute.RunSimple(rc.Ctx, "apt-get", "install", "-y", "auditd", "audispd-plugins"); err != nil {
		return fmt.Errorf("install auditd: %w", err)
	}

	// Write audit rules
	rulesPath := "/etc/audit/rules.d/hardening.rules"
	if err := os.WriteFile(rulesPath, []byte(auditRules), 0644); err != nil {
		return fmt.Errorf("write audit rules: %w", err)
	}
	logger.Info("Audit rules written", zap.String("path", rulesPath))

	// Restart and enable auditd
	if err := execute.RunSimple(rc.Ctx, "systemctl", "restart", "auditd"); err != nil {
		return fmt.Errorf("restart auditd: %w", err)
	}

	if err := execute.RunSimple(rc.Ctx, "systemctl", "enable", "auditd"); err != nil {
		return fmt.Errorf("enable auditd: %w", err)
	}

	logger.Info("✅ Auditd configured and started")
	return nil
}