// cmd/delphi/deploy/deploy.go

package deploy

import (
	"github.com/spf13/cobra"
)

// InstallCmd is the root command for Delphi installation actions
var InstallCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy Delphi components",
	Long: `Commands to install Wazuh/Delphi components like docker-listener.
For example:
  eos delphi deploy docker-listener`,
}

// In the init function, attach subcommands (for example, the Trivy installer).
func init() {
	DeployCmd.AddCommand(DockerListenerCmd)
}
