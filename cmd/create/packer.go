// cmd/create/packer.go
package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/packer"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var CreatePackerCmd = &cobra.Command{
	Use:   "packer",
	Short: "Install HashiCorp Packer on any supported platform",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)
		log.Info("🚀 Installing Packer")
		return packer.EnsureInstalled(rc, zap.L())
	}),
}

func init() {
	CreateCmd.AddCommand(CreatePackerCmd)
}
