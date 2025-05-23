// cmd/create/packer.go
package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/packer"
	"github.com/spf13/cobra"
)

var CreatePackerCmd = &cobra.Command{
	Use:   "packer",
	Short: "Install HashiCorp Packer on any supported platform",
	RunE: eoscli.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Logger()
		log.Info("🚀 Installing Packer")
		return packer.EnsureInstalled(log)
	}),
}

func init() {
	CreateCmd.AddCommand(CreatePackerCmd)
}