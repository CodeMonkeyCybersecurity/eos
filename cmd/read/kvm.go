//go:build linux

// cmd/read/kvm.go

package read

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
)

var ListKvmCmd = &cobra.Command{
	Use:   "kvm --all",
	Short: "List all KVM VMs with state, network, MAC, protocol, and IP",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return kvm.PrintAllVMsTable()
	}),
}

func init() {
	ReadCmd.AddCommand(ListKvmCmd)
}
