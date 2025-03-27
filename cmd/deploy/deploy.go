package deploy

import (
	"eos/pkg/logger"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var log *zap.Logger

// DeployCmd is the root command for deployment-related tasks.
var DeployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy various components",
	Long: `Deploy commands allow you to provision additional components or dependencies.
For example:
	eos deploy trivy 
	eos deploy vault
	eos deploy umami`,
}

func init() {
	// Initialize the shared logger for the entire deploy package
	log = logger.GetLogger()

	// Attach subcommands
	DeployCmd.AddCommand(trivyCmd)
	DeployCmd.AddCommand(vaultCmd)
	DeployCmd.AddCommand(umamiCmd)
	DeployCmd.AddCommand(jenkinsCmd)
	DeployCmd.AddCommand(zabbixCmd)
}
