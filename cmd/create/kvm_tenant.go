// cmd/create/kvm_tenant.go

package create

import (
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
)

var CreateKvmTenantCmd = &cobra.Command{
	Use:   "tenant",
	Short: "Provision a new KVM tenant VM using CentOS Stream 9 or cloud-init",
	Long: `Provision a new tenant virtual machine under KVM.

By default, this creates a CentOS Stream 9 VM using a Kickstart-based installation.
You can customize the VM name, injected SSH key, boot ISO, and target OS.

Each VM gets a unique incrementing ID unless you specify --vm-name.

Examples:
  # Create a new tenant VM with default settings
  eos create kvm tenant

  # Create a VM with a specific name and SSH key
  eos create kvm tenant --vm-name vm-tenant-alice --ssh-key ~/.ssh/alice.pub

  # Provision using a custom ISO
  eos create kvm tenant --iso /srv/iso/CentOS-Stream-9.iso

  # (Future) Use Ubuntu with cloud-init (WIP)
  eos create kvm tenant --distro ubuntu-cloud
`,
	RunE: eos.Wrap(runCreateKvmTenant),
}

func init() {
	defaultKey := filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519.pub")
	CreateKvmTenantCmd.Flags().StringVar(&kvm.SshKeyOverride, "ssh-key", defaultKey, "Path to public SSH key to inject")
	CreateKvmCmd.AddCommand(CreateKvmTenantCmd)
	CreateKvmTenantCmd.Flags().StringVar(&kvm.TenantDistro, "distro", "centos-stream9", "Distro to provision (e.g. centos-stream9, ubuntu-cloud)")
	CreateKvmTenantCmd.Flags().StringVar(&kvm.IsoPathOverride, "iso", kvm.IsoDefaultPath, "Path to bootable ISO")
	CreateKvmTenantCmd.Flags().StringVar(&kvm.UserProvidedVMName, "vm-name", "", "Optional custom name for the tenant VM")
}
