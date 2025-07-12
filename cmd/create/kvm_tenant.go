// cmd/create/kvm_tenant.go

package create

import (
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
)

// kvmTenantCmd provisions a new KVM tenant VM
var kvmTenantCmd = &cobra.Command{
	Use:   "tenant",
	Short: "Provision a new KVM tenant VM using CentOS Stream 9 or cloud-init",
	Long: `Provision a new tenant virtual machine under KVM.

By default, this creates a CentOS Stream 9 VM using a Kickstart-based installation.
You can customize the VM name, injected SSH key, boot ISO, and target OS.

Each VM gets a unique incrementing ID unless you specify --vm-name.

Features:
  - Automated provisioning with Kickstart or cloud-init
  - SSH key injection for secure access
  - Support for multiple Linux distributions
  - Unique VM naming with auto-incrementing IDs
  - Network configuration with bridge networking

Examples:
  # Create a CentOS Stream 9 tenant VM with default settings
  eos create kvm tenant
  
  # Create an Ubuntu tenant VM with custom name
  eos create kvm tenant --distro ubuntu-cloud --vm-name web-server-01
  
  # Create a VM with a specific SSH key
  eos create kvm tenant --ssh-key ~/.ssh/custom_key.pub
  
  # Create a VM using a custom ISO
  eos create kvm tenant --iso /path/to/custom.iso --vm-name custom-vm`,
	RunE: eos.Wrap(kvm.RunCreateKvmTenant),
}

func init() {
	defaultKey := filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519.pub")

	kvmTenantCmd.Flags().StringVar(&kvm.SshKeyOverride, "ssh-key", defaultKey, "Path to public SSH key to inject")
	kvmTenantCmd.Flags().StringVar(&kvm.TenantDistro, "distro", "centos-stream9", "Distro to provision (e.g. centos-stream9, ubuntu-cloud)")
	kvmTenantCmd.Flags().StringVar(&kvm.IsoPathOverride, "iso", kvm.IsoDefaultPath, "Path to bootable ISO")
	kvmTenantCmd.Flags().StringVar(&kvm.UserProvidedVMName, "vm-name", "", "Optional custom name for the tenant VM")
}
