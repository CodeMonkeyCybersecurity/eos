// cmd/create/packer.go
package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/packer"
	"github.com/spf13/cobra"
)

var CreatePackerCmd = &cobra.Command{
	Use:   "packer",
	Short: "Install HashiCorp Packer on any supported platform",
	RunE: eos_cli.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log
		log.Info("🚀 Installing Packer")
		return packer.EnsureInstalled(log)
	}),
}

func init() {
	CreateCmd.AddCommand(CreatePackerCmd)
}
