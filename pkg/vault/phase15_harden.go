// pkg/vault/phase15_harden.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfirmSecureStorage prompts user to re-enter keys to confirm they've been saved.
// This function follows the Assess → Intervene → Evaluate pattern with comprehensive logging.
func ConfirmSecureStorage(rc *eos_io.RuntimeContext, original *api.InitResponse) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Prompt user to re-enter credentials
	logger.Info(" [ASSESS] Prompting user to confirm secure storage of credentials")
	logger.Info("terminal prompt: Please re-enter 3 unseal keys and the root token to confirm you've saved them")

	rekeys, err := interaction.PromptSecrets(rc.Ctx, "Unseal Key", 3)
	if err != nil {
		logger.Error(" Failed to prompt for unseal keys", zap.Error(err))
		return fmt.Errorf("prompt for unseal keys: %w", err)
	}

	reroot, err := interaction.PromptSecrets(rc.Ctx, "Root Token", 1)
	if err != nil {
		logger.Error(" Failed to prompt for root token", zap.Error(err))
		return fmt.Errorf("prompt for root token: %w", err)
	}

	// INTERVENE: Verify entered credentials match original
	logger.Info(" [INTERVENE] Verifying entered credentials match original")

	// Match at least 3 keys
	matched := 0
	for i, input := range rekeys {
		inputHash := crypto.HashString(input)
		logger.Debug("Checking unseal key",
			zap.Int("key_number", i+1),
			zap.String("input_hash", inputHash[:8]+"..."))

		for j, ref := range original.KeysB64 {
			refHash := crypto.HashString(ref)
			if inputHash == refHash {
				matched++
				logger.Debug("Key matched",
					zap.Int("input_key", i+1),
					zap.Int("original_key", j+1))
				break
			}
		}
	}

	rootMatches := crypto.HashString(reroot[0]) == crypto.HashString(original.RootToken)

	// EVALUATE: Report verification results
	logger.Info(" [EVALUATE] Credential verification results",
		zap.Int("keys_matched", matched),
		zap.Int("keys_required", 3),
		zap.Bool("root_token_matches", rootMatches))

	if matched < 3 {
		logger.Error(" [EVALUATE] Insufficient unseal keys matched",
			zap.Int("matched", matched),
			zap.Int("required", 3))
		return fmt.Errorf("reconfirmation failed: only %d of 3 required keys matched", matched)
	}

	if !rootMatches {
		logger.Error(" [EVALUATE] Root token does not match")
		return fmt.Errorf("reconfirmation failed: root token does not match")
	}

	logger.Info(" [EVALUATE] Reconfirmation of unseal material passed successfully")
	logger.Info("terminal prompt: ✓ Credentials verified - you have securely stored your Vault keys")
	return nil
}
