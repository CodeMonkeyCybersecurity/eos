//go:build !linux

// cmd/upgrade/kvm_stub.go
package upgrade

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// KVMCmd is a stub for non-Linux platforms
var KVMCmd = &cobra.Command{
	Use:   "kvm",
	Short: "Upgrade packages and reboot KVM VMs (Linux only)",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return eos_err.NewUserError("KVM upgrade is only available on Linux systems")
	}),
}
