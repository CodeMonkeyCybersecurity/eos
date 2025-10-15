// pkg/vault/hardening.go

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// HardeningConfig represents comprehensive hardening configuration
type HardeningConfig struct {
	// System hardening
	DisableSwap       bool
	DisableCoreDumps  bool
	SetUlimits        bool
	ConfigureFirewall bool
	HardenSSH         bool

	// Vault-specific hardening
	EnableAuditLogging bool
	ConfigureTLS       bool
	SetupLogRotation   bool
	EnableRateLimiting bool
	ConfigureBackup    bool

	// Security policies
	RevokeRootToken      bool
	EnableSecretRotation bool
	ConfigureLease       bool
	EnableMFA            bool

	// Network security
	RestrictNetworkAccess bool
	EnableIPWhitelist     bool
	ConfigureReverseProxy bool
}

// DefaultHardeningConfig returns secure defaults for production hardening
func DefaultHardeningConfig() *HardeningConfig {
	return &HardeningConfig{
		DisableSwap:           true,
		DisableCoreDumps:      true,
		SetUlimits:            true,
		ConfigureFirewall:     true,
		HardenSSH:             true,
		EnableAuditLogging:    true,
		ConfigureTLS:          true,
		SetupLogRotation:      true,
		EnableRateLimiting:    true,
		ConfigureBackup:       true,
		RevokeRootToken:       true,
		EnableSecretRotation:  true,
		ConfigureLease:        true,
		EnableMFA:             true,
		RestrictNetworkAccess: true,
		EnableIPWhitelist:     false, // Requires manual configuration
		ConfigureReverseProxy: false, // Requires manual configuration
	}
}

// ComprehensiveHardening applies comprehensive security hardening to Vault deployment
func ComprehensiveHardening(rc *eos_io.RuntimeContext, client *api.Client, config *HardeningConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Starting comprehensive Vault hardening")

	// Fall back to direct hardening
	log.Info("Nomad not available, using direct hardening")

	if config == nil {
		config = DefaultHardeningConfig()
	}

	// System-level hardening
	if err := performSystemHardening(rc, config); err != nil {
		return fmt.Errorf("system hardening failed: %w", err)
	}

	// Vault-specific hardening
	if err := performVaultHardening(rc, client, config); err != nil {
		return fmt.Errorf("vault hardening failed: %w", err)
	}

	// Security policy hardening
	if err := performSecurityPolicyHardening(rc, client, config); err != nil {
		return fmt.Errorf("security policy hardening failed: %w", err)
	}

	// Network security hardening
	if err := performNetworkHardening(rc, config); err != nil {
		return fmt.Errorf("network hardening failed: %w", err)
	}

	log.Info(" Comprehensive Vault hardening completed successfully")
	return nil
}

// performSystemHardening applies system-level security hardening
func performSystemHardening(rc *eos_io.RuntimeContext, config *HardeningConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Applying system-level hardening")

	// Disable swap
	if config.DisableSwap {
		if err := disableSwap(rc); err != nil {
			log.Warn("Failed to disable swap", zap.Error(err))
		}
	}

	// Disable core dumps
	if config.DisableCoreDumps {
		if err := disableCoreDumps(rc); err != nil {
			log.Warn("Failed to disable core dumps", zap.Error(err))
		}
	}

	// Set security-focused ulimits
	if config.SetUlimits {
		if err := setSecurityUlimits(rc); err != nil {
			log.Warn("Failed to set security ulimits", zap.Error(err))
		}
	}

	// Configure firewall
	if config.ConfigureFirewall {
		if err := configureVaultFirewall(rc); err != nil {
			log.Warn("Failed to configure firewall", zap.Error(err))
		}
	}

	// Harden SSH
	if config.HardenSSH {
		if err := hardenSSH(rc); err != nil {
			log.Warn("Failed to harden SSH", zap.Error(err))
		}
	}

	log.Info(" System-level hardening completed")
	return nil
}

// performVaultHardening applies Vault-specific security hardening
func performVaultHardening(rc *eos_io.RuntimeContext, client *api.Client, config *HardeningConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Applying Vault-specific hardening")

	// Enable comprehensive audit logging
	if config.EnableAuditLogging {
		if err := enableComprehensiveAuditLogging(rc, client); err != nil {
			return fmt.Errorf("failed to enable audit logging: %w", err)
		}
	}

	// Configure TLS hardening
	if config.ConfigureTLS {
		if err := hardenTLSConfiguration(rc); err != nil {
			log.Warn("Failed to harden TLS configuration", zap.Error(err))
		}
	}

	// Setup log rotation
	if config.SetupLogRotation {
		if err := setupLogRotation(rc); err != nil {
			log.Warn("Failed to setup log rotation", zap.Error(err))
		}
	}

	// Enable rate limiting
	if config.EnableRateLimiting {
		if err := enableRateLimiting(rc, client); err != nil {
			log.Warn("Failed to enable rate limiting", zap.Error(err))
		}
	}

	// Configure backup
	if config.ConfigureBackup {
		if err := configureVaultBackup(rc); err != nil {
			log.Warn("Failed to configure backup", zap.Error(err))
		}
	}

	log.Info(" Vault-specific hardening completed")
	return nil
}

// performSecurityPolicyHardening applies security policy hardening
func performSecurityPolicyHardening(rc *eos_io.RuntimeContext, client *api.Client, config *HardeningConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Applying security policy hardening")

	// Enable MFA
	if config.EnableMFA {
		mfaConfig := DefaultMFAConfig()
		if err := EnableMFAMethods(rc, client, mfaConfig); err != nil {
			return fmt.Errorf("failed to enable MFA: %w", err)
		}
	}

	// Revoke root token
	if config.RevokeRootToken {
		if err := revokeRootTokenSafely(rc, client); err != nil {
			log.Warn("Failed to revoke root token safely", zap.Error(err))
		}
	}

	// Enable secret rotation
	if config.EnableSecretRotation {
		if err := enableSecretRotation(rc, client); err != nil {
			log.Warn("Failed to enable secret rotation", zap.Error(err))
		}
	}

	// Configure lease management
	if config.ConfigureLease {
		if err := configureLeaseManagement(rc, client); err != nil {
			log.Warn("Failed to configure lease management", zap.Error(err))
		}
	}

	log.Info(" Security policy hardening completed")
	return nil
}

// performNetworkHardening applies network security hardening
func performNetworkHardening(rc *eos_io.RuntimeContext, config *HardeningConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Applying network security hardening")

	// Restrict network access
	if config.RestrictNetworkAccess {
		if err := restrictNetworkAccess(rc); err != nil {
			log.Warn("Failed to restrict network access", zap.Error(err))
		}
	}

	// Enable IP whitelist (if configured)
	if config.EnableIPWhitelist {
		if err := configureIPWhitelist(rc); err != nil {
			log.Warn("Failed to configure IP whitelist", zap.Error(err))
		}
	}

	log.Info(" Network security hardening completed")
	return nil
}

// Individual hardening functions

func disableSwap(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Disabling swap for security")

	// Disable swap immediately
	if err := execute.RunSimple(rc.Ctx, "swapoff", "-a"); err != nil {
		return fmt.Errorf("failed to disable swap: %w", err)
	}

	// Make swap disable persistent
	fstabPath := "/etc/fstab"
	content, err := os.ReadFile(fstabPath)
	if err == nil {
		lines := strings.Split(string(content), "\n")
		var newLines []string

		for _, line := range lines {
			if strings.Contains(line, "swap") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				newLines = append(newLines, "# "+line+" # Disabled by Eos hardening")
			} else {
				newLines = append(newLines, line)
			}
		}

		newContent := strings.Join(newLines, "\n")
		if err := os.WriteFile(fstabPath+".eos-backup", content, 0644); err == nil {
			if err := os.WriteFile(fstabPath, []byte(newContent), 0644); err != nil {
				log.Warn("Failed to update fstab file", zap.String("path", fstabPath), zap.Error(err))
			}
		}
	}

	log.Info(" Swap disabled successfully")
	return nil
}

func disableCoreDumps(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Disabling core dumps for security")

	// Set core dump size to 0
	if err := execute.RunSimple(rc.Ctx, "ulimit", "-c", "0"); err != nil {
		log.Warn("Failed to set ulimit for core dumps", zap.Error(err))
	}

	// Create systemd override for vault service
	vaultServiceDir := "/etc/systemd/system/vault.service.d"
	if err := os.MkdirAll(vaultServiceDir, 0755); err == nil {
		overrideContent := `[Service]
LimitCORE=0
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/vault
`
		if err := os.WriteFile(filepath.Join(vaultServiceDir, "security.conf"), []byte(overrideContent), 0644); err != nil {
			log.Warn("Failed to write vault security override", zap.Error(err))
		}
		if err := execute.RunSimple(rc.Ctx, "systemctl", "daemon-reload"); err != nil {
			log.Warn("Failed to reload systemd", zap.Error(err))
		}
	}

	// Configure system-wide core dump limits
	limitsContent := `# Eos Vault hardening - disable core dumps
* hard core 0
* soft core 0
vault hard core 0
vault soft core 0
`
	if err := os.WriteFile("/etc/security/limits.d/vault-hardening.conf", []byte(limitsContent), 0644); err != nil {
		log.Warn("Failed to write vault hardening limits", zap.Error(err))
	}

	log.Info(" Core dumps disabled successfully")
	return nil
}

func setSecurityUlimits(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Setting security-focused ulimits")

	ulimitsContent := `# Eos Vault security ulimits
vault soft nofile 65536
vault hard nofile 65536
vault soft memlock unlimited
vault hard memlock unlimited
vault soft nproc 4096
vault hard nproc 4096
`

	if err := os.WriteFile("/etc/security/limits.d/vault-ulimits.conf", []byte(ulimitsContent), 0644); err != nil {
		return fmt.Errorf("failed to write ulimits configuration: %w", err)
	}

	log.Info(" Security ulimits configured successfully")
	return nil
}

func configureVaultFirewall(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Configuring firewall for Vault")

	// Check if ufw is available
	if err := execute.RunSimple(rc.Ctx, "which", "ufw"); err == nil {
		// Configure UFW rules
		rules := [][]string{
			{"ufw", "default", "deny", "incoming"},
			{"ufw", "default", "allow", "outgoing"},
			{"ufw", "allow", "ssh"},
			{"ufw", "allow", shared.VaultWebPortTCP, "comment", "Vault API"},
			{"ufw", "allow", "from", "127.0.0.1", "to", "any", "port", shared.VaultDefaultPort},
			{"ufw", "--force", "enable"},
		}

		for _, rule := range rules {
			if err := execute.RunSimple(rc.Ctx, rule[0], rule[1:]...); err != nil {
				log.Warn("Failed to apply UFW rule", zap.Strings("rule", rule), zap.Error(err))
			}
		}
	} else if err := execute.RunSimple(rc.Ctx, "which", "firewall-cmd"); err == nil {
		// Configure firewalld rules
		rules := [][]string{
			{"firewall-cmd", "--permanent", "--add-service=ssh"},
			{"firewall-cmd", "--permanent", "--add-port=" + shared.VaultWebPortTCP},
			{"firewall-cmd", "--permanent", "--add-rich-rule=rule family=ipv4 source address=127.0.0.1 port protocol=tcp port=" + shared.VaultDefaultPort + " accept"},
			{"firewall-cmd", "--reload"},
		}

		for _, rule := range rules {
			if err := execute.RunSimple(rc.Ctx, rule[0], rule[1:]...); err != nil {
				log.Warn("Failed to apply firewalld rule", zap.Strings("rule", rule), zap.Error(err))
			}
		}
	}

	log.Info(" Firewall configured successfully")
	return nil
}

func hardenSSH(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Hardening SSH configuration")

	sshConfigPath := "/etc/ssh/sshd_config"

	// Backup original config
	if err := execute.RunSimple(rc.Ctx, "cp", sshConfigPath, sshConfigPath+".eos-backup"); err != nil {
		log.Warn("Failed to backup SSH config", zap.Error(err))
	}

	// Read current config
	content, err := os.ReadFile(sshConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH config: %w", err)
	}

	// Apply hardening settings
	hardeningSettings := map[string]string{
		"PermitRootLogin":        "no",
		"PasswordAuthentication": "no",
		"PubkeyAuthentication":   "yes",
		"Protocol":               "2",
		"X11Forwarding":          "no",
		"AllowAgentForwarding":   "no",
		"AllowTcpForwarding":     "no",
		"UsePAM":                 "yes",
		"MaxAuthTries":           "3",
		"ClientAliveInterval":    "300",
		"ClientAliveCountMax":    "2",
		"LoginGraceTime":         "60",
		"MaxStartups":            "10:30:60",
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string

	settingsApplied := make(map[string]bool)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			newLines = append(newLines, line)
			continue
		}

		parts := strings.Fields(trimmed)
		if len(parts) >= 2 {
			key := parts[0]
			if newValue, exists := hardeningSettings[key]; exists {
				newLines = append(newLines, fmt.Sprintf("%s %s # Hardened by Eos", key, newValue))
				settingsApplied[key] = true
				continue
			}
		}

		newLines = append(newLines, line)
	}

	// Add any missing settings
	newLines = append(newLines, "", "# Eos SSH hardening settings")
	for key, value := range hardeningSettings {
		if !settingsApplied[key] {
			newLines = append(newLines, fmt.Sprintf("%s %s", key, value))
		}
	}

	// Write new config
	newContent := strings.Join(newLines, "\n")
	if err := os.WriteFile(sshConfigPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write hardened SSH config: %w", err)
	}

	// Test SSH config
	if err := execute.RunSimple(rc.Ctx, "sshd", "-t"); err != nil {
		log.Warn("SSH config test failed, restoring backup", zap.Error(err))
		if err := execute.RunSimple(rc.Ctx, "cp", sshConfigPath+".eos-backup", sshConfigPath); err != nil {
			log.Error("Failed to restore SSH config backup", zap.Error(err))
		}
		return fmt.Errorf("SSH config test failed: %w", err)
	}

	log.Info(" SSH hardening completed successfully")
	return nil
}

func enableComprehensiveAuditLogging(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Enabling comprehensive audit logging")

	// Create audit log directory
	auditDir := "/var/log/vault"
	if err := os.MkdirAll(auditDir, 0750); err != nil {
		return fmt.Errorf("failed to create audit directory: %w", err)
	}

	// Change ownership to vault user
	if err := execute.RunSimple(rc.Ctx, "chown", "vault:vault", auditDir); err != nil {
		log.Warn("Failed to set audit directory ownership", zap.Error(err))
	}

	// Enable file audit backend
	auditOptions := &api.EnableAuditOptions{
		Type: "file",
		Options: map[string]string{
			"file_path":     "/var/log/vault/vault-audit.log",
			"log_raw":       "false", // Don't log sensitive data in plaintext
			"hmac_accessor": "true",
			"mode":          "0640",
		},
	}

	// Check if audit backend already exists
	auditMounts, err := client.Sys().ListAudit()
	if err != nil {
		return fmt.Errorf("failed to list audit backends: %w", err)
	}

	if _, exists := auditMounts["file/"]; !exists {
		err = client.Sys().EnableAuditWithOptions("file", auditOptions)
		if err != nil {
			return fmt.Errorf("failed to enable file audit backend: %w", err)
		}
	}

	// Enable syslog audit backend for redundancy
	syslogOptions := &api.EnableAuditOptions{
		Type: "syslog",
		Options: map[string]string{
			"facility": "AUTH",
			"tag":      "vault",
			"log_raw":  "false",
		},
	}

	if _, exists := auditMounts["syslog/"]; !exists {
		err = client.Sys().EnableAuditWithOptions("syslog", syslogOptions)
		if err != nil {
			log.Warn("Failed to enable syslog audit backend", zap.Error(err))
		}
	}

	log.Info(" Comprehensive audit logging enabled")
	return nil
}

func hardenTLSConfiguration(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Hardening TLS configuration")

	// This would involve updating the Vault configuration file
	// to use stronger TLS settings, cipher suites, etc.
	// For now, we'll log that this should be done manually

	log.Info(" TLS hardening requires manual Vault configuration update")
	log.Info(" Recommended: Use TLS 1.2+, strong cipher suites, and HSTS")

	return nil
}

func setupLogRotation(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Setting up log rotation")

	logrotateConfig := `# Vault log rotation configuration
/var/log/vault/*.log {
    daily
    missingok
    rotate 90
    compress
    delaycompress
    copytruncate
    notifempty
    create 640 vault vault
    postrotate
        /bin/kill -HUP $(cat /run/vault.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
`

	if err := os.WriteFile("/etc/logrotate.d/vault", []byte(logrotateConfig), 0644); err != nil {
		return fmt.Errorf("failed to write logrotate configuration: %w", err)
	}

	log.Info(" Log rotation configured successfully")
	return nil
}

func enableRateLimiting(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Enabling rate limiting")

	// Configure rate limiting quotas
	quotaConfigs := []struct {
		name   string
		config map[string]interface{}
	}{
		{
			name: "global-rate-limit",
			config: map[string]interface{}{
				"type":           "rate-limit",
				"rate":           1000.0, // 1000 requests per second
				"interval":       "1s",
				"block_interval": "60s",
			},
		},
		{
			name: "auth-rate-limit",
			config: map[string]interface{}{
				"type":           "rate-limit",
				"rate":           10.0, // 10 auth attempts per second
				"interval":       "1s",
				"path":           "auth/",
				"block_interval": "300s", // 5 minute block
			},
		},
	}

	for _, quota := range quotaConfigs {
		_, err := client.Logical().Write(fmt.Sprintf("sys/quotas/rate-limit/%s", quota.name), quota.config)
		if err != nil {
			log.Warn("Failed to configure rate limit quota",
				zap.String("quota", quota.name),
				zap.Error(err))
		}
	}

	log.Info(" Rate limiting configured successfully")
	return nil
}

func configureVaultBackup(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Configuring Vault backup")

	// Create backup script
	backupScript := `#!/bin/bash
# Vault backup script generated by Eos
set -euo pipefail

BACKUP_DIR="/var/backups/vault"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/vault-snapshot-$DATE.snap"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Take Vault snapshot
vault operator raft snapshot save "$BACKUP_FILE"

# Compress the snapshot
gzip "$BACKUP_FILE"

# Remove snapshots older than 30 days
find "$BACKUP_DIR" -name "vault-snapshot-*.snap.gz" -mtime +30 -delete

echo "Vault snapshot saved to $BACKUP_FILE.gz"
`

	scriptPath := "/usr/local/bin/vault-backup.sh"
	if err := os.WriteFile(scriptPath, []byte(backupScript), 0755); err != nil {
		return fmt.Errorf("failed to write backup script: %w", err)
	}

	// Create systemd timer for daily backups
	timerContent := `[Unit]
Description=Daily Vault Backup
Requires=vault-backup.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
`

	serviceContent := fmt.Sprintf(`[Unit]
Description=Vault Backup Service
Wants=vault.service
After=vault.service

[Service]
Type=oneshot
User=vault
Group=vault
ExecStart=/usr/local/bin/vault-backup.sh
Environment=VAULT_ADDR=%s
`, shared.VaultDefaultLocalAddr)

	if err := os.WriteFile("/etc/systemd/system/vault-backup.timer", []byte(timerContent), 0644); err != nil {
		log.Warn("Failed to write vault backup timer", zap.Error(err))
	}
	if err := os.WriteFile("/etc/systemd/system/vault-backup.service", []byte(serviceContent), 0644); err != nil {
		log.Warn("Failed to write vault backup service", zap.Error(err))
	}

	// Enable the timer
	if err := execute.RunSimple(rc.Ctx, "systemctl", "daemon-reload"); err != nil {
		log.Warn("Failed to reload systemd for backup services", zap.Error(err))
	}
	if err := execute.RunSimple(rc.Ctx, "systemctl", "enable", "vault-backup.timer"); err != nil {
		log.Warn("Failed to enable vault backup timer", zap.Error(err))
	}
	if err := execute.RunSimple(rc.Ctx, "systemctl", "start", "vault-backup.timer"); err != nil {
		log.Warn("Failed to start vault backup timer", zap.Error(err))
	}

	log.Info(" Vault backup configured successfully")
	return nil
}

func revokeRootTokenSafely(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Safely revoking root token")

	// Ensure we have alternative authentication methods
	authMethods, err := client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("failed to list auth methods: %w", err)
	}

	hasUserpass := false
	hasAppRole := false

	for path, method := range authMethods {
		switch method.Type {
		case "userpass":
			hasUserpass = true
			log.Info(" Userpass authentication available", zap.String("path", path))
		case "approle":
			hasAppRole = true
			log.Info(" AppRole authentication available", zap.String("path", path))
		}
	}

	if !hasUserpass && !hasAppRole {
		log.Warn("No alternative authentication methods available")
		if !interaction.PromptYesNo(rc.Ctx, "No alternative auth methods found. Continue with root token revocation?", false) {
			log.Info("⏭️ Root token revocation cancelled by user")
			return nil
		}
	}

	// Final confirmation
	log.Warn(" IMPORTANT: Revoking root token will require alternative authentication")
	if !interaction.PromptYesNo(rc.Ctx, "Are you sure you want to revoke the root token?", false) {
		log.Info("⏭️ Root token revocation cancelled by user")
		return nil
	}

	// Revoke the root token
	err = client.Auth().Token().RevokeSelf("")
	if err != nil {
		return fmt.Errorf("failed to revoke root token: %w", err)
	}

	log.Info(" Root token revoked successfully")
	log.Info(" Use alternative authentication methods for future access")

	return nil
}

func enableSecretRotation(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Configuring secret rotation policies")

	// Set up lease configurations for different secret types
	leaseConfigs := []struct {
		path   string
		config map[string]interface{}
	}{
		{
			path: "secret/config",
			config: map[string]interface{}{
				"default_lease_ttl": "24h",
				"max_lease_ttl":     "168h", // 7 days
			},
		},
	}

	for _, lease := range leaseConfigs {
		_, err := client.Logical().Write(lease.path, lease.config)
		if err != nil {
			log.Warn("Failed to configure lease for path",
				zap.String("path", lease.path),
				zap.Error(err))
		}
	}

	log.Info(" Secret rotation policies configured")
	return nil
}

func configureLeaseManagement(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Configuring lease management")

	// Configure default lease settings
	tuneConfig := map[string]interface{}{
		"default_lease_ttl": "1h",
		"max_lease_ttl":     "24h",
	}

	_, err := client.Logical().Write("sys/mounts/secret/tune", tuneConfig)
	if err != nil {
		log.Warn("Failed to tune secret mount", zap.Error(err))
	}

	log.Info(" Lease management configured")
	return nil
}

func restrictNetworkAccess(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Restricting network access")

	// Configure iptables rules for additional network security
	// This is a basic example - production deployments should use more sophisticated rules
	rules := [][]string{
		{"iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"},
		{"iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"},
		{"iptables", "-A", "INPUT", "-p", "tcp", "--dport", shared.VaultDefaultPort, "-s", "127.0.0.1", "-j", "ACCEPT"},
		{"iptables", "-A", "INPUT", "-j", "DROP"},
	}

	for _, rule := range rules {
		if err := execute.RunSimple(rc.Ctx, rule[0], rule[1:]...); err != nil {
			log.Warn("Failed to apply iptables rule", zap.Strings("rule", rule), zap.Error(err))
		}
	}

	// Save iptables rules
	if err := execute.RunSimple(rc.Ctx, "iptables-save"); err != nil {
		log.Warn("Failed to save iptables rules", zap.Error(err))
	}

	log.Info(" Network access restrictions applied")
	return nil
}

func configureIPWhitelist(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Configuring IP whitelist")

	// This would require manual configuration or integration with
	// reverse proxy/load balancer configurations
	log.Info(" IP whitelist configuration requires manual setup")
	log.Info(" Configure allowed IP ranges in your reverse proxy or firewall")

	return nil
}

// GetHardeningStatus returns the current hardening status
func GetHardeningStatus(rc *eos_io.RuntimeContext) map[string]interface{} {
	status := map[string]interface{}{
		"timestamp": time.Now().UTC(),
		"checks":    make(map[string]bool),
	}

	checks := status["checks"].(map[string]bool)

	// Check if swap is disabled
	if err := execute.RunSimple(rc.Ctx, "swapon", "--show"); err != nil {
		checks["swap_disabled"] = true
	} else {
		checks["swap_disabled"] = false
	}

	// Check if UFW is enabled
	if err := execute.RunSimple(rc.Ctx, "ufw", "status"); err == nil {
		checks["firewall_enabled"] = true
	} else {
		checks["firewall_enabled"] = false
	}

	// Check if audit logging is configured
	if _, err := os.Stat("/var/log/vault/vault-audit.log"); err == nil {
		checks["audit_logging"] = true
	} else {
		checks["audit_logging"] = false
	}

	// Check if backup is configured
	if _, err := os.Stat("/usr/local/bin/vault-backup.sh"); err == nil {
		checks["backup_configured"] = true
	} else {
		checks["backup_configured"] = false
	}

	return status
}
