// cmd/undo.go

package undo

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/flags"
	"go.uber.org/zap"
)

var UndoCmd = &cobra.Command{
	Use:   "undo",
	Short: "Undo the last set of system changes made by eos",
	Long: `Attempts to revert the last actions performed by Eos by reading the last recorded action log.
Dry-run by default. Use --live-run to apply changes.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		flags.ParseDryRunAliases(cmd)

		logFile := "/var/lib/eos/actions/latest.yaml" // Placeholder path
		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			fmt.Println("❌ No action log found to undo.")
			return nil
		}

		fmt.Printf("🔍 Reading recorded actions from %s...\n", logFile)

		actions, err := LoadActions(logFile)
		if err != nil {
			return fmt.Errorf("failed to load action log: %w", err)
		}

		for i := len(actions) - 1; i >= 0; i-- {
			act := actions[i]
			if flags.IsDryRun() {
				fmt.Printf("🧪 [dry-run] Would undo: %s → %s\n", act.Type, act.Target)
			} else {
				fmt.Printf("↩️  Undoing: %s → %s...\n", act.Type, act.Target)
				if err := ApplyUndo(act); err != nil {
					fmt.Fprintf(os.Stderr, "❌ Failed to undo %s: %v\n", act.Target, err)
				}
			}
		}

		fmt.Println("✅ Undo complete (dry-run unless --live-run was passed).")
		return nil
	},
}

func init() {
	// Register the command during startup
	flags.AddDryRunFlags(UndoCmd)
}
