// pkg/vault/remember.go
package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
)

func RememberedPrompt(path, key, prompt string, defaultValue string) (string, error) {
	var values map[string]string
	if err := LoadWithFallback(path, &values); err != nil {
		values = make(map[string]string)
	}

	current, ok := values[key]
	if ok {
		use := interaction.PromptSelect(fmt.Sprintf("Use stored value for %s (%s)?", key, current), []string{"Yes", "No"})
		if use == "Yes" {
			return current, nil
		}
	}

	// Otherwise, prompt
	val := interaction.PromptInput(prompt, defaultValue)
	values[key] = val

	if err := SaveToVault(path, values); err != nil {
		return "", fmt.Errorf("failed to save remembered %s to Vault: %w", key, err)
	}

	return val, nil
}
