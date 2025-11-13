// pkg/vault/vault_lifecycle.go

package vault

import (
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// captureVaultLogsOnFailure captures the last 20 lines of Vault's systemd journal logs for debugging purposes.
func captureVaultLogsOnFailure(rc *eos_io.RuntimeContext) {
	otelzap.Ctx(rc.Ctx).Warn(" Hint: Run 'systemctl status vault' or 'journalctl -u vault' to diagnose Vault startup issues")
	out, err := exec.Command("journalctl", "-u", "vault", "-n", "20", "--no-pager").CombinedOutput()
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Failed to capture Vault journal logs", zap.Error(err))
		return
	}
	otelzap.Ctx(rc.Ctx).Error(" Vault systemd logs", zap.String("logs", string(out)))
}
