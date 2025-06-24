// pkg/vault/util_auth_approle.go

package vault

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func WriteAgentPassword(rc *eos_io.RuntimeContext, password string) error {
	otelzap.Ctx(rc.Ctx).Debug("🔏 Writing Vault Agent password to file", zap.String("path", shared.VaultAgentPassPath))

	data := []byte(password + "\n")
	if err := os.WriteFile(shared.VaultAgentPassPath, data, 0600); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to write password file", zap.String("path", shared.VaultAgentPassPath), zap.Error(err))
		return fmt.Errorf("failed to write Vault Agent password to %s: %w", shared.VaultAgentPassPath, err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault Agent password file written",
		zap.String("path", shared.VaultAgentPassPath),
		zap.Int("bytes_written", len(data)))

	return nil
}
