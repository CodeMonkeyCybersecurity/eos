// pkg/vault/phase_init.go

package vault

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"go.uber.org/zap"
)

// PromptUnsealKeys requests 3 unseal keys interactively with hidden input.
func PromptUnsealKeys(log *zap.Logger) ([]string, error) {
	log.Info("🔐 Please enter 3 base64-encoded unseal keys")
	return interaction.PromptSecrets("Unseal Key", 3, log)
}
