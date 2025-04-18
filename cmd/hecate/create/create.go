package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/create/hetzner"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
)

var log = logger.L()

// CreateCmd represents the create command
var CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create resources for Hecate",
	Long: `The create command allows you to create specific resources
needed for your Hecate deployment, such as certificates, proxy configurations, DNS records with Hetzner Cloud, etc.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Instead of printing, use the centralized logger:
		log.Info("Create command executed!",
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
