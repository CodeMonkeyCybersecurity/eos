package ubuntu

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const blacklistNetworkProtocols = `# Disable rare network protocols
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
`

const sysctlSecurityConfig = `# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore Directed pings
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP/IP SYN cookies
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Disable IPv6 if not needed (uncomment to enable)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

# Enable ExecShield (if available)
kernel.randomize_va_space = 2

# Restrict core dumps
fs.suid_dumpable = 0
kernel.core_uses_pid = 1

# Restrict access to kernel logs
kernel.dmesg_restrict = 1

# Restrict ptrace scope
kernel.yama.ptrace_scope = 1
`

func applySystemHardening(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Disable unused network protocols
	blacklistPath := "/etc/modprobe.d/blacklist-rare-network.conf"
	if err := os.WriteFile(blacklistPath, []byte(blacklistNetworkProtocols), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("write network blacklist: %w", err)
	}
	logger.Info("Disabled rare network protocols", zap.String("path", blacklistPath))

	// Set kernel parameters for security
	sysctlPath := "/etc/sysctl.d/99-security.conf"
	if err := os.WriteFile(sysctlPath, []byte(sysctlSecurityConfig), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("write sysctl config: %w", err)
	}
	logger.Info("Security kernel parameters configured", zap.String("path", sysctlPath))

	// Apply sysctl settings
	if err := execute.RunSimple(rc.Ctx, "sysctl", "-p", sysctlPath); err != nil {
		return fmt.Errorf("apply sysctl settings: %w", err)
	}

	// Set secure permissions on sensitive files
	permissions := []struct {
		path string
		mode os.FileMode
	}{
		{"/boot/grub/grub.cfg", 0600},
		{"/etc/passwd", 0644},
		{"/etc/shadow", 0640},
		{"/etc/group", 0644},
		{"/etc/gshadow", 0640},
	}

	for _, p := range permissions {
		// Check if file exists before changing permissions
		if _, err := os.Stat(p.path); err == nil {
			if err := os.Chmod(p.path, p.mode); err != nil {
				logger.Warn("Failed to set permissions",
					zap.String("path", p.path),
					zap.String("mode", fmt.Sprintf("%04o", p.mode)),
					zap.Error(err))
			} else {
				logger.Info("Set secure permissions",
					zap.String("path", p.path),
					zap.String("mode", fmt.Sprintf("%04o", p.mode)))
			}
		}
	}

	logger.Info(" System hardening applied")
	return nil
}

const securityReportScript = `#!/bin/bash
# Generate security report

echo "=== Security Report for $(hostname) - $(date) ==="
echo

echo "=== Failed Login Attempts (last 24h) ==="
journalctl -u ssh.service --since="24 hours ago" | grep "Failed password" | tail -10
echo

echo "=== Current Login Sessions ==="
w
echo

echo "=== Recently Modified System Files ==="
find /etc -type f -mtime -1 -ls 2>/dev/null | head -20
echo

echo "=== Listening Network Ports ==="
ss -tulpn | grep LISTEN
echo

echo "=== Failed Services ==="
systemctl list-units --failed
echo

echo "=== Disk Usage ==="
df -h
echo

echo "=== Recent Security Events (auditd) ==="
aureport --summary
echo

echo "=== Fail2ban Status ==="
fail2ban-client status
echo

echo "=== Osquery File Integrity Monitoring ==="
if command -v security-monitor >/dev/null 2>&1; then
    security-monitor files
else
    echo "  security-monitor not available"
fi
echo

echo "=== Run 'lynis audit system' for detailed security audit ==="
echo "=== Run 'security-monitor' for real-time security monitoring ==="
`

func createSecurityReportScript(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	scriptPath := "/usr/local/bin/security-report"
	if err := os.WriteFile(scriptPath, []byte(securityReportScript), 0755); err != nil {
		return fmt.Errorf("write security report script: %w", err)
	}

	logger.Info(" Security report script created", zap.String("path", scriptPath))
	return nil
}
