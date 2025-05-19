// cmd/create/kvm_template.go

package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/spf13/cobra"
)



var NewKvmTemplateCmd = &cobra.Command {
		Use:   "template",
		Short: "Provision a reusable KVM template image",
		RunE:  eos.Wrap(runCreateKvmTemplate),
	}
}
