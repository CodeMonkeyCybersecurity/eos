/* pkg/vault/remember.go */

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"go.uber.org/zap"
)

//
// ========================== REMEMBER ==========================
//

// pkg/vault/remember.go or a new pkg/vault/bootstrap.go

/**/
// Remember prompts the user for a Vault config field and persists it using fallback logic.
func Remember(name, key, prompt, def string, log *zap.Logger) (string, error) {
	// Attempt to load previously stored secrets.
	values := map[string]string{}
	// We assume loadWithFallback is a Vault-specific function that loads the config
	// from Vault (or falls back to disk) and unmarshals into the map.
	if err := HandleFallbackOrStore(name, values, log); err != nil {
		log.Warn("Fallback config not loaded; may be first-time use", zap.Error(err))
	}

	// Use the generic interaction helper to prompt the user.
	current := values[key] // could be empty if not present
	val := interaction.Remember(key, prompt, def, current, log)
	values[key] = val

	// Persist the updated config using the Vault fallback mechanism.
	if err := HandleFallbackOrStore(name, values, log); err != nil {
		return "", fmt.Errorf("failed to persist %q to Vault or fallback: %w", key, err)
	}

	return val, nil
}

/**/

/**/
func PromptOrRecallUnsealKeys(log *zap.Logger) ([]string, string, error) {
	keys := make([]string, 0, 3)

	for i := 1; i <= 3; i++ {
		key, err := Remember("vault_init", fmt.Sprintf("unseal_key_%d", i), fmt.Sprintf("Enter Unseal Key %d", i), "", log)
		if err != nil {
			return nil, "", err
		}
		keys = append(keys, key)
	}

	root, err := Remember("vault_init", "root_token", "Enter Root Token", "", log)
	if err != nil {
		return nil, "", err
	}

	return keys, root, nil
}

/**/

/**/
func rememberBootstrapHashes(log *zap.Logger) ([]string, string, error) {
	secrets, err := ReadFallbackSecrets(log)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load vault_init fallback secrets: %w", err)
	}

	hashes := []string{
		secrets["unseal_key_1_hash"],
		secrets["unseal_key_2_hash"],
		secrets["unseal_key_3_hash"],
	}
	root := secrets["root_token_hash"]

	return hashes, root, nil
}

/**/
