// cmd/create/kvm_template.go

package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
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
