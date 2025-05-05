// pkg/vault/util_auth_approle.go

package vault

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

func WriteAgentPassword(password string) error {
	zap.L().Debug("🔏 Writing Vault Agent password to file", zap.String("path", shared.VaultAgentPassPath))

	data := []byte(password + "\n")
	if err := os.WriteFile(shared.VaultAgentPassPath, data, 0600); err != nil {
		zap.L().Error("❌ Failed to write password file", zap.String("path", shared.VaultAgentPassPath), zap.Error(err))
		return fmt.Errorf("failed to write Vault Agent password to %s: %w", shared.VaultAgentPassPath, err)
	}

	zap.L().Info("✅ Vault Agent password file written",
		zap.String("path", shared.VaultAgentPassPath),
		zap.Int("bytes_written", len(data)))

	return nil
}
