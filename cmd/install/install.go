// cmd/install/install.go
package install

import (
    	"eos/pkg/logger"
	
    	"go.uber.org/zap"
	
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

// log is a package-level variable for the Zap logger.
var log *zap.Logger

func init() {
    // Initialize the shared logger for the entire install package
    log = logger.GetLogger()
	
    	// Attach subcommands
	InstallCmd.AddCommand(trivyCmd)
	InstallCmd.AddCommand(vaultCmd)
	InstallCmd.AddCommand(umamiCmd)
}
