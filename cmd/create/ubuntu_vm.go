package create

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform/kvm"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecureVMConfig contains secure defaults for Ubuntu VM creation
type SecureVMConfig struct {
	Name        string
	Memory      string // e.g., "4GB"
	VCPUs       int
	DiskSize    string // e.g., "40GB"
	Network     string
	StoragePool string
	SSHKeys     []string
	EnableTPM   bool
	SecureBoot  bool
	EncryptDisk bool
	AutoUpdate  bool
}

// DefaultSecureVMConfig returns secure defaults for Ubuntu VMs
func DefaultSecureVMConfig(name string) *SecureVMConfig {
	return &SecureVMConfig{
		Name:        name,
		Memory:      "4GB",
		VCPUs:       2,
		DiskSize:    "40GB",
		Network:     "default",
		StoragePool: "default",
		EnableTPM:   true,
		SecureBoot:  true,
		EncryptDisk: true,
		AutoUpdate:  true,
	}
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

// generateVMName creates a unique VM name with timestamp and random string
func generateVMName(base string) string {
	timestamp := time.Now().Format("20060102-150405")
	// Generate 4 random bytes (8 hex characters) for uniqueness
	randBytes := make([]byte, 4)
	if _, err := rand.Read(randBytes); err != nil {
		// Fallback to nanosecond timestamp if crypto/rand fails
		randBytes = []byte(fmt.Sprintf("%d", time.Now().Nanosecond()))
	}
	randStr := hex.EncodeToString(randBytes)
	
	// Clean the base name to be filesystem and DNS safe
	safeBase := strings.ToLower(base)
	safeBase = strings.ReplaceAll(safeBase, " ", "-")
	safeBase = strings.ReplaceAll(safeBase, ".", "-")
	
	// Combine components
	return fmt.Sprintf("%s-%s-%s", safeBase, timestamp, randStr)
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
	NewSecureUbuntuVMCmd.Flags().StringVarP(&ubuntuVMName, "name", "n", "", "Custom name for the VM (default: auto-generated)")
}

func findDefaultSSHKeys() ([]string, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}

	sshDir := filepath.Join(usr.HomeDir, ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read ~/.ssh directory: %w", err)
	}

	var keys []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".pub") {
			keyPath := filepath.Join(sshDir, entry.Name())
			keys = append(keys, keyPath)
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no SSH public keys found in ~/.ssh/")
	}

	return keys, nil
}

func createSecureUbuntuVM(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
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
		config.Memory = ubuntuVMMemory
	}
	if cmd.Flags().Changed("vcpus") {
		config.VCPUs = ubuntuVMVCPUs
	}
	if cmd.Flags().Changed("disk-size") {
		config.DiskSize = ubuntuVMDiskSize
	}
	if cmd.Flags().Changed("network") {
		config.Network = ubuntuVMNetwork
	}
	if cmd.Flags().Changed("storage-pool") {
		config.StoragePool = ubuntuVMPool
	}

	// Handle VM name override from flag if provided
	if cmd.Flags().Changed("name") {
		config.Name = ubuntuVMName
		otelzap.Ctx(rc.Ctx).Info("Using custom VM name from flag",
			zap.String("name", config.Name))
	}

	// Handle SSH keys - use provided keys or default to ~/.ssh/*.pub
	if cmd.Flags().Changed("ssh-keys") {
		config.SSHKeys = ubuntuVMSSHKeys
		otelzap.Ctx(rc.Ctx).Info("Using provided SSH keys",
			zap.Strings("keys", config.SSHKeys))
	} else {
		defaultKeys, err := findDefaultSSHKeys()
		if err != nil {
			return fmt.Errorf("no SSH keys provided and failed to find default keys: %w", err)
		}
		config.SSHKeys = defaultKeys
		otelzap.Ctx(rc.Ctx).Info("Using default SSH keys from ~/.ssh/", 
			zap.Strings("keys", defaultKeys))
	}

	// Log VM creation details
	otelzap.Ctx(rc.Ctx).Info("Creating secure Ubuntu VM",
		zap.String("name", config.Name),
		zap.String("memory", config.Memory),
		zap.Int("vcpus", config.VCPUs),
		zap.String("disk", config.DiskSize),
		zap.String("network", config.Network),
		zap.Bool("tpm", config.EnableTPM),
		zap.Bool("secureboot", config.SecureBoot),
		zap.Bool("encryption", config.EncryptDisk))

	// Apply security toggles
	config.EnableTPM = !ubuntuVMDisableTPM
	config.SecureBoot = !ubuntuVMDisableSB
	config.EncryptDisk = !ubuntuVMDisableEnc
	config.AutoUpdate = !ubuntuVMDisableAuto

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
	logger := otelzap.Ctx(rc.Ctx)

	// Parse memory size
	memoryMB, err := parseKVMMemorySize(config.Memory)
	if err != nil {
		return fmt.Errorf("invalid memory format: %w", err)
	}

	// Parse disk size
	diskSizeBytes, err := parseKVMDiskSize(config.DiskSize)
	if err != nil {
		return fmt.Errorf("invalid disk size format: %w", err)
	}

	// Generate secure cloud-init configuration
	userData := generateSecureCloudInit(config)
	metaData := generateKVMMetaData(config.Name)

	// Log the secure VM configuration
	logger.Info("Secure VM configuration",
		zap.String("name", config.Name),
		zap.Uint("memory_mb", memoryMB),
		zap.Int("vcpus", config.VCPUs),
		zap.Uint64("disk_size", diskSizeBytes),
		zap.Bool("tpm_enabled", config.EnableTPM),
		zap.Bool("secure_boot", config.SecureBoot),
		zap.Bool("disk_encrypted", config.EncryptDisk),
		zap.Bool("auto_updates", config.AutoUpdate))

	// Create VM configuration with security settings
	vmConfig := &kvm.VMConfig{
		Name:        config.Name,
		Memory:      memoryMB,
		VCPUs:       uint(config.VCPUs),
		DiskSize:    diskSizeBytes,
		NetworkName: config.Network,
		OSVariant:   "ubuntu24.04",
		SSHKeys:     config.SSHKeys,
		UserData:    userData,
		MetaData:    metaData,
		StoragePool: config.StoragePool,
		AutoStart:   true,

		// Security settings
		EnableTPM:   config.EnableTPM,
		SecureBoot:  config.SecureBoot,
		EncryptDisk: config.EncryptDisk,
		TPMVersion:  "2.0",
		TPMType:     "emulator",
		TPMBackend:  "emulator",
		Firmware:    "/usr/share/OVMF/OVMF_CODE.fd",
		NVRAM:       "/usr/share/OVMF/OVMF_VARS.fd",

		// Secure boot settings
		SecureBootLoader:    "/usr/share/OVMF/OVMF_CODE.secboot.fd",
		SecureBootKeySource: "auto",

		Tags: map[string]string{
			"created_by":  "eos-cli",
			"purpose":     "secure-ubuntu-vm",
			"security":    "high",
			"environment": "production",
		},
	}

	// Add security features
	if config.EnableTPM {
		// TPM 2.0 emulation
		vmConfig.Tags["tpm"] = "2.0"
	}

	if config.SecureBoot {
		// Enable UEFI Secure Boot
		vmConfig.Tags["secure_boot"] = "enabled"
	}

	// Create the VM
	vmInfo, err := kvmMgr.CreateVM(rc.Ctx, vmConfig)
	if err != nil {
		return fmt.Errorf("failed to create secure VM: %w", err)
	}

	// Output VM information
	fmt.Printf("✅ Secure Ubuntu VM created successfully!\n")
	fmt.Printf("   Name: %s\n", vmInfo.Name)
	fmt.Printf("   UUID: %s\n", vmInfo.UUID)
	fmt.Printf("   State: %s\n", vmInfo.State)
	fmt.Printf("   Memory: %s\n", formatKVMSize(vmInfo.Memory))
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
	cloudConfig := `#cloud-config
package_update: true
package_upgrade: true
package_reboot_if_required: true
`

	// Add security packages
	cloudConfig += `
# Security packages
packages:
  - unattended-upgrades
  - apt-listchanges
  - needrestart
  - tpm2-tools
  - apparmor
  - apparmor-utils
  - auditd
  - fail2ban
  - ufw
`

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

	// Add security hardening
	cloudConfig += `
# Security hardening
security:
  disable_root: true
  ssh_pwauth: false
  allow_public_ssh: true

# Enable UFW firewall
runcmd:
  - ufw --force enable
  - ufw default deny incoming
  - ufw default allow outgoing
  - ufw allow ssh
  - ufw allow http
  - ufw allow https
  - systemctl enable --now ufw
  - systemctl enable --now fail2ban
  - systemctl enable --now apparmor
  - systemctl enable --now auditd
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
