// cmd/read/kvm.go

package read

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
)

var ListKvmCmd = &cobra.Command{
	Use:   "kvm --all",
	Short: "List all KVM VMs with state, network, MAC, protocol, and IP",
	RunE: eoscli.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		return kvm.PrintAllVMsTable()
	}),
}

func init() {
	ReadCmd.AddCommand(ListKvmCmd)
}
