// cmd/delphi/deploy/deploy.go

package deploy

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
)

// InstallCmd is the root command for Delphi installation actions
var DeployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy Delphi components",
	Long: `Commands to install Wazuh/Delphi components like docker-listener.
For example:
  eos delphi deploy docker-listener`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		return nil
	}),
}

// In the init function, attach subcommands (for example, the Trivy installer).
func init() {
	DeployCmd.AddCommand(DockerListenerCmd)
}
