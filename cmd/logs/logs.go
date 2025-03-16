package logs

import (
	"github.com/spf13/cobra"
)

// LogsCmd represents the parent "logs" command.
var LogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Log related commands",
	Long:  "Commands for viewing and tailing logs for various components.",
}
