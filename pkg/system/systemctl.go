// pkg/system/systemctl.go
package system

import (
	"fmt"
	"os/exec"

	"go.uber.org/zap"
)

// ReloadDaemonAndEnable reloads systemd, then enables & starts the given unit.
// It returns an error if either step fails.
func ReloadDaemonAndEnable(log *zap.Logger, unit string) error {
	// 1) reload systemd
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		log.Warn("systemd daemon-reload failed",
			zap.Error(err),
			zap.ByteString("output", out),
		)
		return fmt.Errorf("daemon-reload: %w", err)
	}

	// 2) enable & start the unit
	if out, err := exec.Command("systemctl", "enable", "--now", unit).CombinedOutput(); err != nil {
		log.Warn("failed to enable/start service",
			zap.String("unit", unit),
			zap.Error(err),
			zap.ByteString("output", out),
		)
		return fmt.Errorf("enable --now %s: %w", unit, err)
	}

	log.Info("✅ systemd unit enabled & started",
		zap.String("unit", unit),
	)
	return nil
}
