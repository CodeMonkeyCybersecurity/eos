// pkg/system/systemctl.go
package system

import (
	"fmt"
	"os/exec"
	"time"

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

func StartSystemdUnitWithRetry(log *zap.Logger, unit string, retries int, delaySeconds int) error {
	return RunSystemctlWithRetry(log, "start", unit, retries, delaySeconds)
}

func StopSystemdUnitWithRetry(log *zap.Logger, unit string, retries int, delaySeconds int) error {
	return RunSystemctlWithRetry(log, "stop", unit, retries, delaySeconds)
}

func RestartSystemdUnitWithRetry(log *zap.Logger, unit string, retries int, delaySeconds int) error {
	return RunSystemctlWithRetry(log, "restart", unit, retries, delaySeconds)
}

// RunSystemctlWithRetry runs a systemctl command with retries, logging, and error context.
// Valid actions: "start", "stop", "restart", etc.
func RunSystemctlWithRetry(log *zap.Logger, action, unit string, retries, delaySeconds int) error {
	log.Info("⚙️ systemctl action initiated",
		zap.String("action", action),
		zap.String("unit", unit),
	)

	var lastErr error
	for i := 0; i < retries; i++ {
		cmd := exec.Command("systemctl", action, unit)
		out, err := cmd.CombinedOutput()

		if err == nil {
			log.Info(fmt.Sprintf("✅ systemd unit %s succeeded", action),
				zap.String("unit", unit),
			)
			return nil
		}

		log.Warn(fmt.Sprintf("⚠️ systemctl %s failed", action),
			zap.Int("attempt", i+1),
			zap.String("unit", unit),
			zap.Error(err),
			zap.ByteString("output", out),
		)
		lastErr = err
		time.Sleep(time.Duration(delaySeconds) * time.Second)
	}

	log.Error(fmt.Sprintf("❌ systemd unit %s failed after retries", action),
		zap.String("unit", unit),
		zap.Error(lastErr),
	)
	log.Info("🩺 Run `systemctl status " + unit + " -l` or `journalctl -u " + unit + "` to investigate further")

	return fmt.Errorf("systemctl %s for unit %q failed: %w", action, unit, lastErr)
}
