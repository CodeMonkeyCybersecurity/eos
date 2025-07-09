// cmd/create/kvm_template.go

package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
)

// kvmTemplateCmd provisions a reusable KVM template image
var kvmTemplateCmd = &cobra.Command{
	Use:   "template",
	Short: "Provision a reusable KVM template image",
	Long: `Provision a reusable KVM template image for rapid VM deployment.

This command creates a base template VM that can be cloned to quickly provision
new virtual machines with pre-configured settings and software.

Features:
  - Creates optimized base images for various OS distributions
  - Configures cloud-init for automated provisioning
  - Installs common packages and configurations
  - Prepares images for rapid cloning

Examples:
  # Create an Ubuntu template
  eos create kvm template --name ubuntu-22.04-template --os ubuntu-22.04
  
  # Create a Rocky Linux template with custom disk size
  eos create kvm template --name rocky-9-template --os rocky-9 --disk 50G
  
  # Create a template with additional packages
  eos create kvm template --name dev-template --packages git,docker,python3`,
	RunE: eos.Wrap(kvm.RunCreateKvmTemplate),
}