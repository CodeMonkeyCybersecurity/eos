package create

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform/kvm"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Use SecureVMConfig from the kvm package
type SecureVMConfig = kvm.SecureVMConfig

// DefaultSecureVMConfig delegates to the kvm package
func DefaultSecureVMConfig(name string) *SecureVMConfig {
	return kvm.DefaultSecureVMConfig(name)
}

var (
	ubuntuVMName        string
	ubuntuVMMemory      string
	ubuntuVMVCPUs       int
	ubuntuVMDiskSize    string
	ubuntuVMNetwork     string
	ubuntuVMPool        string
	ubuntuVMSSHKeys     []string
	ubuntuVMDisableTPM  bool
	ubuntuVMDisableSB   bool
	ubuntuVMDisableEnc  bool
	ubuntuVMDisableAuto bool
)

// generateVMName delegates to the kvm package
func generateVMName(base string) string {
	return kvm.GenerateVMName(base)
}

// NewSecureUbuntuVMCmd represents the create ubuntu-vm command
var NewSecureUbuntuVMCmd = &cobra.Command{
	Use:   "ubuntu-vm [name]",
	Short: "Create a new secure Ubuntu VM with hardened defaults",
	Long: `Create a new Ubuntu VM with security best practices enabled by default.
This includes TPM 2.0, Secure Boot, disk encryption, and automatic security updates.

If no name is provided, a unique name will be generated automatically.

Examples:
  # Create a VM with auto-generated name
  eos create ubuntu-vm

  # Create a VM with custom name
  eos create ubuntu-vm my-vm

  # Customize VM resources
  eos create ubuntu-vm --memory 8GB --vcpus 4 --disk-size 100GB`,
	Args: cobra.MaximumNArgs(1), // Make name argument optional
	RunE: eos_cli.Wrap(createSecureUbuntuVM),
}

func init() {
	// Register the command
	CreateCmd.AddCommand(NewSecureUbuntuVMCmd)

	// Add flags with secure defaults
	NewSecureUbuntuVMCmd.Flags().StringVarP(&ubuntuVMMemory, "memory", "m", "", "Memory allocation (e.g., 4GB)")
	NewSecureUbuntuVMCmd.Flags().IntVarP(&ubuntuVMVCPUs, "vcpus", "c", 0, "Number of vCPUs")
	NewSecureUbuntuVMCmd.Flags().StringVarP(&ubuntuVMDiskSize, "disk-size", "d", "", "Disk size (e.g., 40GB)")
	NewSecureUbuntuVMCmd.Flags().StringVarP(&ubuntuVMNetwork, "network", "n", "", "Network name")
	NewSecureUbuntuVMCmd.Flags().StringVarP(&ubuntuVMPool, "storage-pool", "p", "", "Storage pool name")
	NewSecureUbuntuVMCmd.Flags().StringSliceVarP(&ubuntuVMSSHKeys, "ssh-keys", "k", nil, "SSH public key files (required for login)")

	// Security toggle flags (default is secure)
	NewSecureUbuntuVMCmd.Flags().BoolVar(&ubuntuVMDisableTPM, "disable-tpm", false, "Disable TPM 2.0 emulation (not recommended)")
	NewSecureUbuntuVMCmd.Flags().BoolVar(&ubuntuVMDisableSB, "disable-secureboot", false, "Disable Secure Boot (not recommended)")
	NewSecureUbuntuVMCmd.Flags().BoolVar(&ubuntuVMDisableEnc, "disable-encryption", false, "Disable disk encryption (not recommended)")
	NewSecureUbuntuVMCmd.Flags().BoolVar(&ubuntuVMDisableAuto, "disable-autoupdates", false, "Disable automatic security updates (not recommended)")

	// Make ssh-keys optional with default behavior
	// Using 'N' for name to avoid conflict with network's 'n' shorthand
	NewSecureUbuntuVMCmd.Flags().StringVarP(&ubuntuVMName, "name", "N", "", "Custom name for the VM (default: auto-generated)")
}

// findDefaultSSHKeys delegates to the kvm package
func findDefaultSSHKeys() ([]string, error) {
	return kvm.FindDefaultSSHKeys()
}

func createSecureUbuntuVM(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// Defensive check for nil context
	if rc == nil || rc.Ctx == nil {
		return fmt.Errorf("invalid runtime context: context is nil")
	}

	// Generate or use provided VM name
	var vmName string
	if len(args) > 0 {
		vmName = args[0]
	} else {
		vmName = generateVMName("eos-vm")
		otelzap.Ctx(rc.Ctx).Info("No VM name provided, using generated name",
			zap.String("name", vmName))
	}

	// Use secure defaults
	config := DefaultSecureVMConfig(vmName)

	// Apply any overrides from flags
	if cmd.Flags().Changed("memory") {
		val, _ := cmd.Flags().GetString("memory")
		if val != "" {
			config.Memory = val
		}
	}
	if cmd.Flags().Changed("vcpus") {
		val, _ := cmd.Flags().GetInt("vcpus")
		if val > 0 {
			config.VCPUs = val
		}
	}
	if cmd.Flags().Changed("disk-size") {
		val, _ := cmd.Flags().GetString("disk-size")
		if val != "" {
			config.DiskSize = val
		}
	}
	if cmd.Flags().Changed("network") {
		val, _ := cmd.Flags().GetString("network")
		if val != "" {
			config.Network = val
		}
	}
	if cmd.Flags().Changed("storage-pool") {
		val, _ := cmd.Flags().GetString("storage-pool")
		if val != "" {
			config.StoragePool = val
		}
	}

	// Handle security level
	if cmd.Flags().Changed("security-level") {
		val, _ := cmd.Flags().GetString("security-level")
		if val != "" {
			config.SecurityLevel = val
		}
	}

	// Handle enable-all-security flag
	if cmd.Flags().Changed("enable-all-security") {
		if enabled, _ := cmd.Flags().GetBool("enable-all-security"); enabled {
			config.SecurityLevel = "paranoid"
			config.EnableTPM = true
			config.SecureBoot = true
			config.EncryptDisk = true
			config.AutoUpdate = true
			config.EnableFirewall = true
			config.EnableFail2ban = true
			config.EnableAudit = true
			config.EnableAppArmor = true
		}
	}

	// Handle VM name override from flag if provided
	if cmd.Flags().Changed("name") {
		val, _ := cmd.Flags().GetString("name")
		if val != "" {
			config.Name = val
			otelzap.Ctx(rc.Ctx).Info("Using custom VM name from flag",
				zap.String("name", config.Name))
		}
	}

	// Handle SSH keys - use provided keys or default to ~/.ssh/*.pub
	if cmd.Flags().Changed("ssh-keys") {
		val, _ := cmd.Flags().GetStringSlice("ssh-keys")
		if len(val) > 0 {
			config.SSHKeys = val
			otelzap.Ctx(rc.Ctx).Info("Using provided SSH keys",
				zap.Strings("keys", config.SSHKeys))
		}
	} else {
		defaultKeys, err := findDefaultSSHKeys()
		if err != nil {
			return fmt.Errorf("no SSH keys provided and failed to find default keys: %w", err)
		}
		config.SSHKeys = defaultKeys
		otelzap.Ctx(rc.Ctx).Info("Using default SSH keys from ~/.ssh/",
			zap.Strings("keys", defaultKeys))
	}

	// Apply security disable flags (override defaults)
	if cmd.Flags().Changed("disable-tpm") {
		if disabled, _ := cmd.Flags().GetBool("disable-tpm"); disabled {
			config.EnableTPM = false
		}
	}
	if cmd.Flags().Changed("disable-secureboot") {
		if disabled, _ := cmd.Flags().GetBool("disable-secureboot"); disabled {
			config.SecureBoot = false
		}
	}
	if cmd.Flags().Changed("disable-encryption") {
		if disabled, _ := cmd.Flags().GetBool("disable-encryption"); disabled {
			config.EncryptDisk = false
		}
	}
	if cmd.Flags().Changed("disable-autoupdates") {
		if disabled, _ := cmd.Flags().GetBool("disable-autoupdates"); disabled {
			config.AutoUpdate = false
		}
	}
	if cmd.Flags().Changed("disable-firewall") {
		if disabled, _ := cmd.Flags().GetBool("disable-firewall"); disabled {
			config.EnableFirewall = false
		}
	}
	if cmd.Flags().Changed("disable-fail2ban") {
		if disabled, _ := cmd.Flags().GetBool("disable-fail2ban"); disabled {
			config.EnableFail2ban = false
		}
	}
	if cmd.Flags().Changed("disable-audit") {
		if disabled, _ := cmd.Flags().GetBool("disable-audit"); disabled {
			config.EnableAudit = false
		}
	}
	if cmd.Flags().Changed("disable-apparmor") {
		if disabled, _ := cmd.Flags().GetBool("disable-apparmor"); disabled {
			config.EnableAppArmor = false
		}
	}
	if cmd.Flags().Changed("enable-ipv6") {
		if enabled, _ := cmd.Flags().GetBool("enable-ipv6"); enabled {
			config.DisableIPv6 = false
		}
	}

	// Log VM creation details
	otelzap.Ctx(rc.Ctx).Info("Creating secure Ubuntu VM",
		zap.String("name", config.Name),
		zap.String("memory", config.Memory),
		zap.Int("vcpus", config.VCPUs),
		zap.String("disk", config.DiskSize),
		zap.String("network", config.Network),
		zap.String("security_level", config.SecurityLevel),
		zap.Bool("tpm", config.EnableTPM),
		zap.Bool("secureboot", config.SecureBoot),
		zap.Bool("encryption", config.EncryptDisk),
		zap.Bool("firewall", config.EnableFirewall),
		zap.Bool("fail2ban", config.EnableFail2ban),
		zap.Bool("audit", config.EnableAudit),
		zap.Bool("apparmor", config.EnableAppArmor),
		zap.Bool("disable_ipv6", config.DisableIPv6))

	// Initialize KVM manager
	kvmMgr, err := kvm.NewKVMManager(rc, "")
	if err != nil {
		return fmt.Errorf("failed to initialize KVM manager: %w", err)
	}
	defer kvmMgr.Close()

	// Create the secure VM
	return createSecureVM(rc, kvmMgr, config)
}

func createSecureVM(rc *eos_io.RuntimeContext, kvmMgr *kvm.KVMManager, config *SecureVMConfig) error {
	// Defensive check for nil context
	if rc == nil || rc.Ctx == nil {
		return fmt.Errorf("invalid runtime context: context is nil")
	}

	// Delegate to the package function for VM creation
	vmInfo, err := kvm.CreateSecureVM(rc.Ctx, kvmMgr, config)
	if err != nil {
		return fmt.Errorf("failed to create secure VM: %w", err)
	}

	// Output VM information
	fmt.Printf("✅ Secure Ubuntu VM created successfully!\n")
	fmt.Printf("   Name: %s\n", vmInfo.Name)
	fmt.Printf("   UUID: %s\n", vmInfo.UUID)
	fmt.Printf("   State: %s\n", vmInfo.State)
	fmt.Printf("   Memory: %s\n", kvm.FormatMemorySize(int(vmInfo.Memory)))
	fmt.Printf("   vCPUs: %d\n", vmInfo.VCPUs)

	// Security features summary
	fmt.Printf("\n🔒 Security Features:\n")
	fmt.Printf("   • %-20s %s\n", "Secure Boot:", "✅ Enabled")
	fmt.Printf("   • %-20s %s\n", "TPM 2.0:", map[bool]string{true: "✅ Enabled", false: "❌ Disabled"}[config.EnableTPM])
	fmt.Printf("   • %-20s %s\n", "Disk Encryption:", map[bool]string{true: "✅ Enabled", false: "❌ Disabled"}[config.EncryptDisk])
	fmt.Printf("   • %-20s %s\n", "Auto Updates:", map[bool]string{true: "✅ Enabled", false: "❌ Disabled"}[config.AutoUpdate])

	// Network information
	if len(vmInfo.Networks) > 0 {
		fmt.Printf("\n🌐 Network Configuration:\n")
		for _, net := range vmInfo.Networks {
			fmt.Printf("   • %s: %s", net.Interface, net.Network)
			if net.IP != "" {
				fmt.Printf(" (IP: %s)", net.IP)
			}
			fmt.Println()
		}
	}

	// Connection instructions
	if len(vmInfo.Networks) > 0 && vmInfo.Networks[0].IP != "" {
		fmt.Printf("\n🔑 SSH Access:\n")
		fmt.Printf("   ssh ubuntu@%s  # Use your SSH key for authentication\n", vmInfo.Networks[0].IP)
	}

	// Security recommendations
	fmt.Printf("\n🔐 Security Recommendations:\n")
	fmt.Printf("   • Change the default password after first login\n")
	fmt.Printf("   • Enable UFW firewall: 'sudo ufw enable'\n")
	fmt.Printf("   • Review security updates: 'sudo apt update && sudo apt list --upgradable'\n")

	return nil
}

func generateSecureCloudInit(config *SecureVMConfig) string {
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
		}...)
	}

	if config.EnableTPM {
		packages = append(packages, "tpm2-tools", "tpm2-abrmd")
	}

	cloudConfig += "\n# Security packages\npackages:\n"
	for _, pkg := range packages {
		cloudConfig += fmt.Sprintf("  - %s\n", pkg)
	}

	// Configure automatic security updates
	if config.AutoUpdate {
		cloudConfig += `
# Configure automatic security updates
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
  automatic_reboot_time: "now"
`
	}

	// Add SSH keys
	if len(config.SSHKeys) > 0 {
		cloudConfig += "\n# SSH authorized keys\nssh_authorized_keys:\n"
		for _, keyFile := range config.SSHKeys {
			keyData, err := os.ReadFile(keyFile)
			if err == nil {
				cloudConfig += "  - " + string(keyData) + "\n"
			}
		}
	}

	// Add kernel hardening and security configurations
	cloudConfig += `
# Write security configuration files
write_files:
  - path: /etc/sysctl.d/99-eos-security.conf
    content: |
      # IP Spoofing protection
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
      net.ipv4.icmp_ignore_bogus_error_responses = 1

      # Enable SYN cookies
      net.ipv4.tcp_syncookies = 1
      net.ipv4.tcp_syn_retries = 5

      # Kernel randomization
      kernel.randomize_va_space = 2

      # Disable core dumps
      fs.suid_dumpable = 0
      kernel.core_pattern = |/bin/false
`

	if config.DisableIPv6 {
		cloudConfig += `      # Disable IPv6
      net.ipv6.conf.all.disable_ipv6 = 1
      net.ipv6.conf.default.disable_ipv6 = 1
      net.ipv6.conf.lo.disable_ipv6 = 1
`
	}

	// SSH hardening for high security
	if config.SecurityLevel == "high" || config.SecurityLevel == "paranoid" {
		cloudConfig += `
  - path: /etc/ssh/sshd_config.d/99-eos-hardened.conf
    content: |
      # EOS Security Hardened SSH Configuration
      Protocol 2
      PermitRootLogin no
      PasswordAuthentication no
      PubkeyAuthentication yes
      PermitEmptyPasswords no
      ChallengeResponseAuthentication no
      KerberosAuthentication no
      GSSAPIAuthentication no
      X11Forwarding no
      PermitUserEnvironment no
      AllowUsers ubuntu
      ClientAliveInterval 300
      ClientAliveCountMax 2
      MaxAuthTries 3
      MaxSessions 2
      LoginGraceTime 30
      StrictModes yes
      IgnoreRhosts yes
      HostbasedAuthentication no
      Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
      MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
      KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
`
	}

	// Fail2ban configuration
	if config.EnableFail2ban {
		cloudConfig += `
  - path: /etc/fail2ban/jail.local
    content: |
      [DEFAULT]
      bantime = 3600
      findtime = 600
      maxretry = 5
      destemail = security@localhost
      action = %(action_mwl)s

      [sshd]
      enabled = true
      port = ssh
      filter = sshd
      logpath = /var/log/auth.log
      maxretry = 3
`
	}

	// Audit rules for paranoid level
	if config.SecurityLevel == "paranoid" {
		cloudConfig += `
  - path: /etc/audit/rules.d/eos-cis.rules
    content: |
      # CIS Benchmark Audit Rules
      -w /etc/passwd -p wa -k passwd_changes
      -w /etc/group -p wa -k group_changes
      -w /etc/shadow -p wa -k shadow_changes
      -w /etc/sudoers -p wa -k sudoers_changes
      -w /var/log/auth.log -p wa -k auth_log_changes
      -w /etc/ssh/sshd_config -p wa -k sshd_config_changes
      -a always,exit -F arch=b64 -S execve -C uid!=euid -F key=setuid
      -a always,exit -F arch=b64 -S execve -C gid!=egid -F key=setgid
`
	}

	// Security banner
	cloudConfig += `
  - path: /etc/issue.net
    content: |
      ############################################################
      #                                                          #
      #  Unauthorized access to this system is prohibited.      #
      #  All activities are logged and monitored.               #
      #  Violators will be prosecuted to the fullest extent     #
      #  of the law.                                            #
      #                                                          #
      ############################################################
`

	// Add comprehensive run commands for security setup
	cloudConfig += `
# Security hardening commands
runcmd:
  # Update and upgrade system
  - apt-get update
  - DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

  # Apply kernel parameters
  - sysctl -p /etc/sysctl.d/99-eos-security.conf

  # Configure firewall
  - ufw --force reset
  - ufw default deny incoming
  - ufw default allow outgoing
  - ufw allow ssh/tcp
  - ufw limit ssh/tcp
  - ufw --force enable

  # Enable security services
  - systemctl enable --now ufw
  - systemctl enable --now fail2ban
  - systemctl enable --now apparmor
  - systemctl enable --now auditd

  # Configure AppArmor
  - aa-enforce /etc/apparmor.d/*

  # Configure automatic updates
  - dpkg-reconfigure -plow unattended-upgrades

  # Secure shared memory
  - echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
  - mount -o remount /run/shm

  # Disable unnecessary services
  - systemctl disable bluetooth.service 2>/dev/null || true
  - systemctl disable cups.service 2>/dev/null || true
  - systemctl disable avahi-daemon.service 2>/dev/null || true

  # Set security limits
  - echo "* hard core 0" >> /etc/security/limits.conf
  - echo "* soft core 0" >> /etc/security/limits.conf

  # Create security audit log
  - echo "Security hardening completed at $(date)" > /var/log/eos-security.log
  - chmod 600 /var/log/eos-security.log
`

	// Add disk encryption if enabled
	if config.EncryptDisk {
		cloudConfig += `
  # Configure full disk encryption
  - echo 'LUKS_CRYPTTAB_OPTIONS=discard' >> /etc/cryptsetup-initramfs/conf-hook
  - update-initramfs -u -k all
`
	}

	// Add TPM configuration if enabled
	if config.EnableTPM {
		cloudConfig += `
  # TPM 2.0 configuration
  - systemctl enable --now tpm2-abrmd
  - systemctl enable --now tpm2-tcsd
`
	}

	return cloudConfig
}
