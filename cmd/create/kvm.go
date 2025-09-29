// cmd/create/kvm.go

package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

var CreateKvmCmd = &cobra.Command{
	Use:   "kvm",
	Short: "Manage KVM virtual machines and infrastructure",
	Long: `Create and manage KVM/QEMU virtual machines with enterprise-grade security.

Subcommands:
  ubuntu    - Create a security-hardened Ubuntu VM
  install   - Install KVM infrastructure
  tenant    - Manage KVM tenants
  template  - Manage VM templates

Examples:
  # Create a secure Ubuntu VM
  eos create kvm ubuntu my-vm

  # Create Ubuntu VM with shorthand
  eos create kvm --ubuntu my-vm`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// If --ubuntu flag is provided, run ubuntu VM creation
		if ubuntu, _ := cmd.Flags().GetBool("ubuntu"); ubuntu {
			// Delegate to ubuntu VM creation
			return createSecureUbuntuVM(rc, cmd, args)
		}
		return cmd.Help()
	}),
}

// kvmUbuntuCmd represents the ubuntu subcommand under kvm
var kvmUbuntuCmd = &cobra.Command{
	Use:   "ubuntu [name]",
	Short: "Create a security-hardened Ubuntu VM",
	Long: `Create a security-hardened Ubuntu virtual machine using KVM/QEMU.

The VM is created with comprehensive security features enabled by default:
- CIS benchmark hardening with kernel parameter tuning
- Full disk encryption (LUKS)
- TPM 2.0 emulation
- UEFI Secure Boot
- AppArmor mandatory access control
- Automated security updates
- Fail2ban intrusion prevention
- System audit logging
- UFW firewall with rate limiting
- SSH hardening with modern ciphers
- Disabled unnecessary services
- Secure shared memory
- Core dump prevention

Security Levels:
  basic     - Essential security features only
  moderate  - Standard security hardening (default for dev)
  high      - Enhanced security with monitoring (default)
  paranoid  - Maximum security with all features enabled

Examples:
  # Create VM with auto-generated name and high security
  eos create kvm ubuntu

  # Create VM with custom name
  eos create kvm ubuntu prod-server

  # Create VM with custom resources
  eos create kvm ubuntu dev-vm --memory 8GB --vcpus 4 --disk-size 100GB

  # Create VM with paranoid security level
  eos create kvm ubuntu secure-vm --security-level paranoid

  # Create VM with all security features
  eos create kvm ubuntu fortress --enable-all-security`,
	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(createSecureUbuntuVM),
}

func init() {
	CreateCmd.AddCommand(CreateKvmCmd)

	// Add ubuntu subcommand
	CreateKvmCmd.AddCommand(kvmUbuntuCmd)

	// Add existing subcommands
	CreateKvmCmd.AddCommand(kvmInstallCmd)
	CreateKvmCmd.AddCommand(kvmTenantCmd)
	CreateKvmCmd.AddCommand(kvmTemplateCmd)

	// Add --ubuntu flag to kvm command for shorthand
	CreateKvmCmd.Flags().Bool("ubuntu", false, "Create Ubuntu VM (shorthand for 'kvm ubuntu')")

	// Setup flags for kvm ubuntu command
	setupKVMUbuntuFlags(kvmUbuntuCmd)

	// Also add the same flags to the main kvm command for --ubuntu shorthand
	setupKVMUbuntuFlags(CreateKvmCmd)
}

func setupKVMUbuntuFlags(cmd *cobra.Command) {
	// Resource configuration
	cmd.Flags().StringP("memory", "m", "", "Memory allocation (default: 4GB)")
	cmd.Flags().IntP("vcpus", "c", 0, "Number of vCPUs (default: 2)")
	cmd.Flags().StringP("disk-size", "d", "", "Disk size (default: 40GB)")
	cmd.Flags().StringP("network", "n", "", "Network name (default: default)")
	cmd.Flags().StringP("storage-pool", "p", "", "Storage pool name (default: default)")
	cmd.Flags().StringSliceP("ssh-keys", "k", nil, "SSH public key files (auto-detects from ~/.ssh if not specified)")

	// Security configuration
	cmd.Flags().String("security-level", "high", "Security level: basic, moderate, high, paranoid")
	cmd.Flags().Bool("enable-all-security", false, "Enable all security features (sets level to paranoid)")

	// Flags to disable security features (not recommended)
	cmd.Flags().Bool("disable-tpm", false, "Disable TPM 2.0 emulation (not recommended)")
	cmd.Flags().Bool("disable-secureboot", false, "Disable Secure Boot (not recommended)")
	cmd.Flags().Bool("disable-encryption", false, "Disable disk encryption (not recommended)")
	cmd.Flags().Bool("disable-autoupdates", false, "Disable automatic security updates (not recommended)")
	cmd.Flags().Bool("disable-firewall", false, "Disable UFW firewall (not recommended)")
	cmd.Flags().Bool("disable-fail2ban", false, "Disable fail2ban (not recommended)")
	cmd.Flags().Bool("disable-audit", false, "Disable audit logging (not recommended)")
	cmd.Flags().Bool("disable-apparmor", false, "Disable AppArmor (not recommended)")
	cmd.Flags().Bool("enable-ipv6", false, "Enable IPv6 (disabled by default for security)")

	// VM name flag (for consistency)
	cmd.Flags().StringP("name", "N", "", "Custom name for the VM (default: auto-generated)")

	// Additional options
	cmd.Flags().Bool("auto-start", false, "Auto-start VM on host boot")
	cmd.Flags().Bool("dry-run", false, "Show what would be created without actually creating")
	cmd.Flags().Bool("skip-verify", false, "Skip post-deployment verification")
}
