// pkg/vault/remember.go
package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
)

// Remember prompts the user for a Vault config field and persists it using fallback logic.
func remember(name, key, prompt, def string) (string, error) {
	// Attempt to load previously stored secrets.
	values := map[string]string{}
	// We assume loadWithFallback is a Vault-specific function that loads the config
	// from Vault (or falls back to disk) and unmarshals into the map.
	if err := handleFallbackOrStore(name, values); err != nil {
		// Not fatal — the fallback file might not exist yet.
	}

	// Use the generic interaction helper to prompt the user.
	current := values[key] // could be empty if not present
	val := interaction.RememberValue(key, prompt, def, current)
	values[key] = val

	// Persist the updated config using the Vault fallback mechanism.
	if err := handleFallbackOrStore(name, values); err != nil {
		return "", fmt.Errorf("failed to persist %q to Vault or fallback: %w", key, err)
	}

	return val, nil
}
