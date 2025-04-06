package undo

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/flags"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	undoengine "github.com/CodeMonkeyCybersecurity/eos/pkg/undo" // 👈 alias to avoid name clash
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var UndoCmd = &cobra.Command{
	Use:   "undo",
	Short: "Undo the last set of system changes made by eos",
	Long: `Attempts to revert the last actions performed by Eos by reading the last recorded action log.
Dry-run by default. Use --live-run to apply changes.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		flags.ParseDryRunAliases(cmd)
		log := logger.L()

		logDir := undoengine.GetActionLogDir()
		logFile := logDir + "/latest.json"

		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			log.Warn("No action log found to undo", zap.String("file", logFile))
			fmt.Println("❌ No action log found to undo.")
			return nil
		}

		log.Info("Reading recorded actions", zap.String("path", logFile))
		actions, err := undoengine.LoadActions(logFile)
		if err != nil {
			log.Error("Failed to load actions", zap.Error(err))
			return fmt.Errorf("failed to load action log: %w", err)
		}

		for i := len(actions) - 1; i >= 0; i-- {
			act := actions[i]
			if flags.IsDryRun() {
				fmt.Printf("🧪 [dry-run] Would undo: %s → %s\n", act.Type, act.Target)
			} else {
				fmt.Printf("↩️  Undoing: %s → %s...\n", act.Type, act.Target)
				if err := undoengine.ApplyUndo(act); err != nil {
					log.Warn("Undo failed", zap.String("target", act.Target), zap.Error(err))
					fmt.Fprintf(os.Stderr, "❌ Failed to undo %s: %v\n", act.Target, err)
				}
			}
		}

		log.Info("Undo complete")
		fmt.Println("✅ Undo complete (dry-run unless --live-run was passed).")
		return nil
	},
}

func init() {
	flags.AddDryRunFlags(UndoCmd)
}
