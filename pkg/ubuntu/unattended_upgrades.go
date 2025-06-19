package ubuntu

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const unattendedUpgradesConfig = `Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
    "${distro_id}:${distro_codename}-updates";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
`

const autoUpgradesConfig = `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
`

func configureUnattendedUpgrades(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Install unattended-upgrades
	if err := execute.RunSimple(rc.Ctx, "apt-get", "install", "-y", "unattended-upgrades", "apt-listchanges"); err != nil {
		return fmt.Errorf("install unattended-upgrades: %w", err)
	}

	// Configure unattended-upgrades
	configPath := "/etc/apt/apt.conf.d/50unattended-upgrades"
	if err := os.WriteFile(configPath, []byte(unattendedUpgradesConfig), 0644); err != nil {
		return fmt.Errorf("write unattended-upgrades config: %w", err)
	}
	logger.Info("Unattended upgrades configured", zap.String("path", configPath))

	// Enable automatic updates
	autoPath := "/etc/apt/apt.conf.d/20auto-upgrades"
	if err := os.WriteFile(autoPath, []byte(autoUpgradesConfig), 0644); err != nil {
		return fmt.Errorf("write auto-upgrades config: %w", err)
	}
	logger.Info("Automatic updates enabled", zap.String("path", autoPath))

	logger.Info("✅ Automatic security updates configured")
	return nil
}

func installRestic(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Install restic
	if err := execute.RunSimple(rc.Ctx, "apt-get", "install", "-y", "restic"); err != nil {
		return fmt.Errorf("install restic: %w", err)
	}

	// Create restic wrapper script
	scriptPath := "/usr/local/bin/restic-backup"
	scriptContent := `#!/bin/bash
# Restic backup wrapper script
# Configure these variables according to your backup destination

# Example configuration (modify as needed):
# export RESTIC_REPOSITORY="/backup/restic-repo"
# export RESTIC_PASSWORD="your-secure-password"
# Or use a password file:
# export RESTIC_PASSWORD_FILE="/root/.restic-password"

# Directories to backup
BACKUP_PATHS="/etc /home /root /var/log"

# Run backup
restic backup $BACKUP_PATHS \
    --exclude="/var/log/journal/*" \
    --exclude="/var/log/lastlog" \
    --tag="automated"

# Cleanup old snapshots (keep last 7 daily, 4 weekly, 12 monthly)
restic forget --prune \
    --keep-daily 7 \
    --keep-weekly 4 \
    --keep-monthly 12
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return fmt.Errorf("write restic backup script: %w", err)
	}

	// Create example restic password file
	passwordPath := "/root/.restic-password"
	if err := os.WriteFile(passwordPath, []byte("CHANGE_THIS_PASSWORD\n"), 0600); err != nil {
		return fmt.Errorf("write restic password file: %w", err)
	}

	logger.Info("✅ Restic backup solution installed",
		zap.String("script", scriptPath),
		zap.String("note", "Remember to configure backup destination and password"))
	return nil
}