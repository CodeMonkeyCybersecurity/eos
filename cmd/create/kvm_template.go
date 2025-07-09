// cmd/create/kvm_template.go
// TODO: PATTERN 1 - Transform NewKvmTemplateCmd() function to kvmTemplateCmd variable

package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
)

func NewKvmTemplateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Provision a reusable KVM template image",
		RunE:  eos.Wrap(kvm.RunCreateKvmTemplate),
	}
	return cmd
}
