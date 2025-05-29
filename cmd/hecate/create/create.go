// cmd/hecate/create/create.gop

package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/create/hetzner"
)

// CreateCmd represents the create command
var CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create resources for Hecate",
	Long: `The create command allows you to create specific resources
needed for your Hecate deployment, such as certificates, proxy configurations, DNS records with Hetzner Cloud, etc.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Instead of printing, use the centralized logger:
		otelzap.Ctx(rc.Ctx).Info("Create command executed!",
			zap.String("command", cmd.Name()),
			zap.Strings("args", args),
		)
		return nil
	}),
}

// init gets called automatically at package load time
func init() {
	// Attach the hetzner-dns subcommand here
	CreateCmd.AddCommand(hetzner.NewCreateHetznerWildcardCmd())
}
