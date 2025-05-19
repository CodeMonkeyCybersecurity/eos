// cmd/create/kvm_tenant.go

package create

import (
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
)

func NewKvmTenantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tenant",
		Short: "Provision a new KVM tenant VM using CentOS Stream 9 or cloud-init",
		Long: `Provision a new tenant virtual machine under KVM.

By default, this creates a CentOS Stream 9 VM using a Kickstart-based installation.
You can customize the VM name, injected SSH key, boot ISO, and target OS.

Each VM gets a unique incrementing ID unless you specify --vm-name.
`,
		RunE: eos.Wrap(kvm.RunCreateKvmTenant),
	}

	defaultKey := filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519.pub")

	cmd.Flags().StringVar(&kvm.SshKeyOverride, "ssh-key", defaultKey, "Path to public SSH key to inject")
	cmd.Flags().StringVar(&kvm.TenantDistro, "distro", "centos-stream9", "Distro to provision (e.g. centos-stream9, ubuntu-cloud)")
	cmd.Flags().StringVar(&kvm.IsoPathOverride, "iso", kvm.IsoDefaultPath, "Path to bootable ISO")
	cmd.Flags().StringVar(&kvm.UserProvidedVMName, "vm-name", "", "Optional custom name for the tenant VM")

	return cmd
}
