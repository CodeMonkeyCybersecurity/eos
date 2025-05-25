// cmd/list/placeholder.go

package list

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// placeholderListExample is a stub example subcommand for `eos list`
var placeholderListExample = &cobra.Command{
	Use:   "example",
	Short: "List example placeholder data",
	Long:  "This is a placeholder subcommand under 'eos list' for demonstration purposes.",
	RunE: eos_cli.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log
		log.Info("📋 Executing placeholder list subcommand", zap.String("subcommand", "example"))

		// Placeholder output
		fmt.Println("This is a placeholder output for `eos list example`.")

		return nil
	}),
}

func init() {
	ListCmd.AddCommand(placeholderListExample)
}
