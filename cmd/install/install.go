// cmd/install/install.go
package install

import (
	"github.com/spf13/cobra"
)

// InstallCmd is the root command for installation-related tasks.
var InstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install various components",
	Long: `Install commands allow you to provision additional components or dependencies.
For example:
  eos install trivy 
  eos install vault`,
}

// In the init function, attach subcommands (for example, the Trivy installer).
func init() {
	InstallCmd.AddCommand(trivyCmd)
	InstallCmd.AddCommand(vaultCmd)
}
