package create

import (
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"eos/cmd/hecate/create/hetzner"
	"eos/pkg/logger"
)

var log = logger.L()

// CreateCmd represents the create command
var CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create resources for Hecate",
	Long: `The create command allows you to create specific resources
needed for your Hecate deployment, such as certificates, proxy configurations, DNS records with Hetzner Cloud, etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Instead of printing, use the centralized logger:
		log.Info("Create command executed!",
			zap.String("command", cmd.Name()),
			zap.Strings("args", args),
		)
	},
}

// init gets called automatically at package load time
func init() {
	// Attach the hetzner-dns subcommand here
	CreateCmd.AddCommand(hetzner.NewCreateHetznerWildcardCmd())
}
