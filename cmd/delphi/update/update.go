package update

import (
	"fmt"

	"github.com/spf13/cobra"
)

var UpdateCmd = &cobra.Command{
	Use:     "update",
	Aliases: []string{"set", "change"},
	Short:   "Update Delphi resources",
	Long:    "Update configuration and user information in your Delphi (Wazuh) instance.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🔄 Updating Delphi configuration or components...")
	},
}

func init() {
	// Will be registered by root or parent{
	// in update/password.go
	UpdateCmd.AddCommand(PasswordCmd)
}
