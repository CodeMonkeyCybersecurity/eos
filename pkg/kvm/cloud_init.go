// pkg/kvm/cloud_init.go

package kvm

import (
	"fmt"
	"os"
	"strings"
)

// GenerateSecureCloudInit generates a cloud-init configuration for a secure Ubuntu VM
func GenerateSecureCloudInit(config *SecureVMConfig) string {
	// Start with base configuration
	cloudConfig := fmt.Sprintf(`#cloud-config
hostname: %s
manage_etc_hosts: true
preserve_hostname: false

# System updates
package_update: true
package_upgrade: true
package_reboot_if_required: true

# Create secure default user
users:
  - name: ubuntu
    groups: [sudo]
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    shell: /bin/bash
    lock_passwd: true
`, config.Name)

	// Add comprehensive security packages based on security level
	packages := getSecurityPackages(config)

	cloudConfig += "\n# Security packages\npackages:\n"
	for _, pkg := range packages {
		cloudConfig += fmt.Sprintf("  - %s\n", pkg)
	}

	// Configure automatic security updates
	if config.AutoUpdate {
		cloudConfig += getAutoUpdateConfig()
	}

	// Add SSH keys
	if len(config.SSHKeys) > 0 {
		cloudConfig += "\n# SSH authorized keys\nssh_authorized_keys:\n"
		for _, keyFile := range config.SSHKeys {
			keyData, err := os.ReadFile(keyFile)
			if err == nil {
				cloudConfig += fmt.Sprintf("  - %s\n", strings.TrimSpace(string(keyData)))
			}
		}
	}

	// Add kernel security parameters
	cloudConfig += getKernelSecurityParams(config)

	// Add run commands for additional hardening
	cloudConfig += getSecurityRunCommands(config)

	// Add firewall configuration
	if config.EnableFirewall {
		cloudConfig += getFirewallConfig()
	}

	// Add fail2ban configuration
	if config.EnableFail2ban {
		cloudConfig += getFail2banConfig()
	}

	// Add audit configuration
	if config.EnableAudit {
		cloudConfig += getAuditConfig()
	}

	// Add final reboot
	cloudConfig += `
# Final reboot to apply all settings
power_state:
  mode: reboot
  delay: "+1"
  message: "Rebooting to apply security hardening"
`

	return cloudConfig
}

// getSecurityPackages returns the list of security packages based on the security level
func getSecurityPackages(config *SecureVMConfig) []string {
	packages := []string{
		"qemu-guest-agent",
		"unattended-upgrades",
		"apt-listchanges",
		"needrestart",
		"ufw",
		"fail2ban",
		"apparmor",
		"apparmor-utils",
		"auditd",
		"rsyslog",
		"libpam-tmpdir",
		"libpam-cracklib",
		"debsums",
		"apt-transport-https",
		"ca-certificates",
		"gnupg",
		"lsb-release",
	}

	// Add extra packages for higher security levels
	if config.SecurityLevel == "high" || config.SecurityLevel == "paranoid" {
		packages = append(packages, []string{
			"aide",
			"rkhunter",
			"clamav",
			"clamav-daemon",
			"debsecan",
			"lynis",
			"chkrootkit",
			"acct",
			"sysstat",
		}...)
	}

	if config.SecurityLevel == "paranoid" {
		packages = append(packages, []string{
			"tiger",
			"unhide",
			"arpwatch",
			"checksecurity",
			"logwatch",
		}...)
	}

	if config.EnableTPM {
		packages = append(packages, "tpm2-tools", "tpm2-abrmd")
	}

	return packages
}

// getAutoUpdateConfig returns the automatic update configuration
func getAutoUpdateConfig() string {
	return `
# Configure automatic security updates
apt:
  primary:
    - arches: [default]
      uri: http://archive.ubuntu.com/ubuntu
  security:
    - arches: [default]
      uri: http://security.ubuntu.com/ubuntu

apt_update: true
apt_upgrade: true

unattended_upgrades:
  package_blacklist:
    - linux-aws
    - linux-gcp
    - linux-azure
  origins:
    - security
  update: "1"
  upgrade: "1"
  autoremove: "1"
  autoclean: "1"
  automatic_reboot: true
  automatic_reboot_time: "02:00"
`
}

// getKernelSecurityParams returns kernel security parameters
func getKernelSecurityParams(config *SecureVMConfig) string {
	params := `
# Kernel security parameters (CIS hardening)
bootcmd:
  - echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/99-security.conf
  - echo "kernel.exec-shield = 1" >> /etc/sysctl.d/99-security.conf 2>/dev/null || true
  - echo "kernel.kptr_restrict = 2" >> /etc/sysctl.d/99-security.conf
  - echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.d/99-security.conf
  - echo "kernel.panic = 60" >> /etc/sysctl.d/99-security.conf
  - echo "kernel.panic_on_oops = 1" >> /etc/sysctl.d/99-security.conf
  - echo "kernel.modules_disabled = 1" >> /etc/sysctl.d/99-security.conf
`

	// Add network security parameters
	params += `  - echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/99-security.conf
`

	if config.DisableIPv6 {
		params += `  - echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.d/99-security.conf
`
	} else {
		params += `  - echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.d/99-security.conf
  - echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.d/99-security.conf
`
	}

	params += "  - sysctl -p /etc/sysctl.d/99-security.conf\n"
	return params
}

// getSecurityRunCommands returns run commands for additional hardening
func getSecurityRunCommands(config *SecureVMConfig) string {
	commands := `
# Security hardening run commands
runcmd:
  # Enable QEMU guest agent guest-exec for eos monitoring
  # Supports both Debian/Ubuntu and RHEL/CentOS/Rocky/Alma
  - |
    set -e
    echo "eos: Enabling QEMU guest agent guest-exec for monitoring..."

    # Detect OS family and configure appropriate file
    if [ -f /etc/debian_version ] || [ -f /etc/lsb-release ]; then
      # Ubuntu/Debian
      echo "# Managed by eos - enable guest-exec for monitoring" > /etc/default/qemu-guest-agent
      echo 'DAEMON_ARGS=""' >> /etc/default/qemu-guest-agent
      echo "eos: Configured /etc/default/qemu-guest-agent (Debian/Ubuntu)"
    elif [ -f /etc/redhat-release ] || [ -f /etc/centos-release ]; then
      # CentOS/RHEL/Rocky/Alma
      mkdir -p /etc/sysconfig
      echo "# Managed by eos - enable guest-exec for monitoring" > /etc/sysconfig/qemu-ga
      echo 'BLACKLIST_RPC=' >> /etc/sysconfig/qemu-ga
      echo "eos: Configured /etc/sysconfig/qemu-ga (RHEL/CentOS)"
    else
      echo "eos: WARNING - Unknown OS, guest-exec may not be enabled"
      exit 0
    fi

    # Restart guest agent
    if systemctl restart qemu-guest-agent; then
      echo "eos: guest-exec enabled successfully"
    else
      echo "eos: WARNING - Failed to restart qemu-guest-agent"
      exit 0
    fi

    # Log the configuration for audit
    echo "$(date -Iseconds) guest-exec enabled via cloud-init method=automatic" >> /var/log/eos-guest-exec.log

  # Secure shared memory
  - echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
  - mount -o remount /run/shm

  # Disable unused network protocols
  - echo "install dccp /bin/true" >> /etc/modprobe.d/disable-rare-protocols.conf
  - echo "install sctp /bin/true" >> /etc/modprobe.d/disable-rare-protocols.conf
  - echo "install rds /bin/true" >> /etc/modprobe.d/disable-rare-protocols.conf
  - echo "install tipc /bin/true" >> /etc/modprobe.d/disable-rare-protocols.conf

  # Set secure permissions
  - chmod 644 /etc/passwd
  - chmod 640 /etc/shadow
  - chmod 644 /etc/group
  - chmod 640 /etc/gshadow

  # Configure password quality requirements
  - sed -i 's/^# minlen.*/minlen = 14/' /etc/security/pwquality.conf
  - sed -i 's/^# dcredit.*/dcredit = -1/' /etc/security/pwquality.conf
  - sed -i 's/^# ucredit.*/ucredit = -1/' /etc/security/pwquality.conf
  - sed -i 's/^# ocredit.*/ocredit = -1/' /etc/security/pwquality.conf
  - sed -i 's/^# lcredit.*/lcredit = -1/' /etc/security/pwquality.conf

  # Harden SSH configuration
  - sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  - sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  - sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
  - sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
  - sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
  - sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
  - sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
  - sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
  - echo "Protocol 2" >> /etc/ssh/sshd_config
  - echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" >> /etc/ssh/sshd_config
  - echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" >> /etc/ssh/sshd_config
  - echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org" >> /etc/ssh/sshd_config
  - systemctl restart ssh

  # Enable process accounting
  - systemctl enable acct 2>/dev/null || true
  - systemctl start acct 2>/dev/null || true

  # Disable core dumps
  - echo "* hard core 0" >> /etc/security/limits.conf
  - echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-security.conf
  - sysctl -p /etc/sysctl.d/99-security.conf
`

	if config.EnableAppArmor {
		commands += `
  # Enable AppArmor
  - systemctl enable apparmor
  - systemctl start apparmor
  - aa-enforce /etc/apparmor.d/* 2>/dev/null || true
`
	}

	if config.SecurityLevel == "paranoid" {
		commands += `
  # Additional paranoid security measures
  - echo "Authorized users only. All activity is monitored and logged." > /etc/issue
  - echo "Authorized users only. All activity is monitored and logged." > /etc/issue.net
  - chmod 644 /etc/issue /etc/issue.net

  # Restrict su access
  - echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su

  # Set GRUB password (placeholder - needs manual configuration)
  - echo "# GRUB password should be set manually" >> /etc/default/grub
`
	}

	return commands
}

// getFirewallConfig returns UFW firewall configuration
func getFirewallConfig() string {
	return `
  # Configure UFW firewall
  - ufw --force enable
  - ufw default deny incoming
  - ufw default allow outgoing
  - ufw allow 22/tcp
  - ufw limit ssh/tcp
  - ufw logging on
`
}

// getFail2banConfig returns fail2ban configuration
func getFail2banConfig() string {
	return `
  # Configure fail2ban
  - systemctl enable fail2ban
  - |
    cat > /etc/fail2ban/jail.local <<EOF
    [DEFAULT]
    bantime = 3600
    findtime = 600
    maxretry = 3
    destemail = root@localhost
    action = %(action_mwl)s

    [sshd]
    enabled = true
    port = ssh
    filter = sshd
    logpath = /var/log/auth.log
    maxretry = 3
    EOF
  - systemctl restart fail2ban
`
}

// getAuditConfig returns audit configuration
func getAuditConfig() string {
	return `
  # Configure auditd
  - systemctl enable auditd
  - |
    cat >> /etc/audit/rules.d/audit.rules <<EOF
    # Log all commands
    -a exit,always -F arch=b64 -S execve -k commands
    -a exit,always -F arch=b32 -S execve -k commands

    # Log file access
    -w /etc/passwd -p wa -k passwd_changes
    -w /etc/shadow -p wa -k shadow_changes
    -w /etc/group -p wa -k group_changes
    -w /etc/gshadow -p wa -k gshadow_changes
    -w /etc/security/ -p wa -k security_changes

    # Log system calls
    -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
    -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change

    # Log network changes
    -a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_changes
    -a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_changes

    # Make configuration immutable
    -e 2
    EOF
  - systemctl restart auditd
`
}
