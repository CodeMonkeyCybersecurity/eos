// pkg/vault/remember.go
package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
)

// Remember prompts the user for a field and persists it to Vault or fallback.
func remember(name, key, prompt, def string) (string, error) {
	path := vaultPath(name)
	return rememberedPrompt(path, key, prompt, def)
}

// rememberedPrompt prompts for a value, storing and recalling from Vault or fallback.
func rememberedPrompt(path, key, prompt, defaultValue string) (string, error) {
	values := make(map[string]string)

	_ = loadWithFallback(path, &values) // non-fatal if not found

	// Offer to reuse existing value
	if current, ok := values[key]; ok {
		if interaction.PromptSelect(fmt.Sprintf("Use stored value for %s (%s)?", key, current), []string{"Yes", "No"}) == "Yes" {
			return current, nil
		}
	}

	// Prompt user for input
	val := interaction.PromptInput(prompt, defaultValue)
	values[key] = val

	if err := Save(path, values); err != nil {
		return "", fmt.Errorf("failed to save remembered %q to Vault: %w", key, err)
	}

	return val, nil
}
