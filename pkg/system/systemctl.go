// pkg/system/systemctl.go
package system

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"time"

	"go.uber.org/zap"
)

// ReloadDaemonAndEnable reloads systemd, then enables & starts the given unit.
// It returns an error if either step fails.
func ReloadDaemonAndEnable(log *zap.Logger, unit string) error {
	// 1) reload systemd
	if out, err := exec.Command("sudo", "systemctl", "daemon-reload").CombinedOutput(); err != nil {
		log.Warn("systemd daemon-reload failed",
			zap.Error(err),
			zap.ByteString("output", out),
		)
		return fmt.Errorf("daemon-reload: %w", err)
	}

	// 2) enable & start the unit
	if out, err := exec.Command("sudo", "systemctl", "enable", "--now", unit).CombinedOutput(); err != nil {
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

func RunSystemctlWithRetry(log *zap.Logger, action, unit string, retries, delaySeconds int) error {
	log.Info("⚙️ systemctl action initiated",
		zap.String("action", action),
		zap.String("unit", unit),
	)

	if !CanSudoSystemctl("status", unit) {
		if !CanInteractiveSudo() {
			return fmt.Errorf("❌ eos user missing sudo permissions; please add:\n    eos ALL=(ALL) NOPASSWD: /bin/systemctl")
		}
		log.Warn("⚠️ NOPASSWD sudo missing. Attempting interactive sudo...")
		if err := PromptAndRunInteractiveSystemctl(action, unit); err != nil {
			return fmt.Errorf("interactive systemctl %s %s failed: %w", action, unit, err)
		}
		log.Info("✅ Interactive sudo succeeded; skipping retries")
		return nil
	}

	var lastErr error
	for i := 0; i < retries; i++ {
		cmd := exec.Command("sudo", "systemctl", action, unit)
		out, err := cmd.CombinedOutput()

		if bytes.Contains(out, []byte("Authentication is required")) {
			log.Error("❌ Insufficient sudo privileges. Please add to sudoers...",
				zap.String("recommendation", "eos ALL=(ALL) NOPASSWD: /bin/systemctl"))
			return fmt.Errorf("sudo privileges missing; systemctl %s %s requires password", action, unit)
		}

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

// CanSudoSystemctl checks if the current user can run sudo systemctl <action> <unit> without a password.
// Example: CanSudoSystemctl("status", "vault")
func CanSudoSystemctl(action, unit string) bool {
	cmd := exec.Command("sudo", "systemctl", action, unit)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("❌ sudo -n systemctl %s %s failed: %v\n", action, unit, err)
		return false
	}
	return true
}

func PromptAndRunInteractiveSystemctl(action, unit string) error {
	fmt.Printf("⚠️ Privilege escalation required to run 'systemctl %s %s'\n", action, unit)
	fmt.Println("\nYou will be prompted for your password.")

	cmd := exec.Command("sudo", "systemctl", action, unit)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
