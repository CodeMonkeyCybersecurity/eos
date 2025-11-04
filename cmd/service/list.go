package service

import (
	"sort"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/internal/service"
	eos_cli "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// ListCmd enumerates discoverable service definitions.
var ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available service definitions",
	Long: `Lists all service definitions discovered across the configured search
paths. Definitions are sourced from --config overrides, the local repository,
user configuration directories, and /opt/eos/services.`,
	Args: cobra.NoArgs,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		names, err := service.ListDefinitions()
		if err != nil {
			return err
		}

		if len(names) == 0 {
			cmd.Println("No service definitions were found. Add YAML definitions under ./services or ~/.config/eos/services.")
			return nil
		}

		sort.Strings(names)
		cmd.Println("Available service definitions:")
		for _, name := range names {
			cmd.Println(" - " + strings.TrimSpace(name))
		}
		return nil
	}),
}
