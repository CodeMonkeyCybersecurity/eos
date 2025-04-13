/* pkg/vault/remember.go */

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
)

// Remember prompts the user for a Vault config field and persists it using fallback logic.
func Remember(name, key, prompt, def string) (string, error) {
	// Attempt to load previously stored secrets.
	values := map[string]string{}
	// We assume loadWithFallback is a Vault-specific function that loads the config
	// from Vault (or falls back to disk) and unmarshals into the map.
	if err := HandleFallbackOrStore(name, values); err != nil {
		// Not fatal — the fallback file might not exist yet.
	}

	// Use the generic interaction helper to prompt the user.
	current := values[key] // could be empty if not present
	val := interaction.RememberValue(key, prompt, def, current)
	values[key] = val

	// Persist the updated config using the Vault fallback mechanism.
	if err := HandleFallbackOrStore(name, values); err != nil {
		return "", fmt.Errorf("failed to persist %q to Vault or fallback: %w", key, err)
	}

	return val, nil
}

func PromptOrRecallUnsealKeys() ([]string, string, error) {
	keys := make([]string, 0, 3)

	for i := 1; i <= 3; i++ {
		key, err := Remember("vault_init", fmt.Sprintf("unseal_key_%d", i), fmt.Sprintf("Enter Unseal Key %d", i), "")
		if err != nil {
			return nil, "", err
		}
		keys = append(keys, key)
	}

	root, err := Remember("vault_init", "root_token", "Enter Root Token", "")
	if err != nil {
		return nil, "", err
	}

	return keys, root, nil
}
