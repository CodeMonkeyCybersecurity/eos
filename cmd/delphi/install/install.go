// cmd/delphi/install/install.go
package install

import (
	"github.com/spf13/cobra"
)

// InstallCmd is the root command for Delphi installation actions
var InstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Delphi components",
	Long:  `Commands to install Wazuh/Delphi components like docker-listener.
For example:
  eos delphi install docker-listener`,
}

// In the init function, attach subcommands (for example, the Trivy installer).
func init() {
	InstallCmd.AddCommand(DockerListenerCmd)
}
