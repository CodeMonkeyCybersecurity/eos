// cmd/disable/disable.go

package disable

import (
	"github.com/spf13/cobra"
)

var DisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable system features (e.g., suspension, hibernation)",
}

func init() {
	DisableCmd.AddCommand(disableSuspensionCmd)
}
