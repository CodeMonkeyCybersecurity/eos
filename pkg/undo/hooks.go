// pkg/undo/hooks.go

package undo

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/flags"
	"go.uber.org/zap"
)

// FinalizeIfLiveRun writes the undo log if the command actually mutated the system.
func FinalizeIfLiveRun(log *zap.Logger) {
	if flags.IsLiveRun() {
		if err := SaveActionLog(); err != nil {
			log.Warn("❌ Failed to write undo log", zap.Error(err))
		} else {
			log.Info("📝 Undo log saved successfully")
		}
	}
}
