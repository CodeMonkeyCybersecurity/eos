// pkg/vault/vault_lifecycle.go

package vault

import (
	"os/exec"

	"go.uber.org/zap"
)

// captureVaultLogsOnFailure captures the last 20 lines of Vault's systemd journal logs for debugging purposes.
func captureVaultLogsOnFailure() {
	zap.L().Warn("💡 Hint: Run 'systemctl status vault' or 'journalctl -u vault' to diagnose Vault startup issues")
	out, err := exec.Command( "journalctl", "-u", "vault", "-n", "20", "--no-pager").CombinedOutput()
	if err != nil {
		zap.L().Warn("⚠️ Failed to capture Vault journal logs", zap.Error(err))
		return
	}
	zap.L().Error("🚨 Vault systemd logs", zap.String("logs", string(out)))
}
