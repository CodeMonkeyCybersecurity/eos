// cmd/update/for_microsoft.go
package update

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/clean"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// command-scoped flag
var flagMicrosoft bool

// MicrosoftCleanCmd sanitises path names for Windows / Microsoft limits.
var MicrosoftCleanCmd = &cobra.Command{
	Use:   "for-microsoft <path>",
	Short: "Sanitise filenames so they are Microsoft-compatible",
	Long: `Rename a file or recursively rename every file/dir in a tree
so that they respect Windows filename restrictions (reserved device names,
forbidden runes, trailing spaces/dots, etc.).`,
	Args: cobra.ExactArgs(1),

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		if !flagMicrosoft { // flag is required for symmetry with legacy CLI
			return cmd.Help()
		}

		target := args[0]
		info, err := os.Stat(target)
		if err != nil {
			return fmt.Errorf("path not found: %w", err)
		}

		if info.IsDir() {
			return clean.WalkAndSanitize(target)
		}
		return clean.RenameIfNeeded(target)
	}),
}

func init() {
	// flag registration must happen *after* the variable is defined
	MicrosoftCleanCmd.Flags().BoolVar(&flagMicrosoft, "for-microsoft", false,
		"apply Microsoft-safe filename sanitisation (required)")
	CleanCmd.AddCommand(MicrosoftCleanCmd)
}
