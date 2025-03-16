package enable

import (
	"github.com/spf13/cobra"
)

// EnableCmd represents the parent "enable" command.
var EnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Commands to enable or start services",
	Long:  "Commands to enable or start services, such as initializing and unsealing Vault.",
}
