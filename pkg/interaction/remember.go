/* pkg/interaction/remember.go */

package interaction

import (
	"fmt"

	"go.uber.org/zap"
)

// FallbackOption is already defined in your fallback package, so we assume that's available.

// RememberValue prompts the user to either reuse an existing value or enter a new one.
// It returns the chosen value.
func Remember(field, prompt, defaultValue, currentValue string, log *zap.Logger) string {
	if currentValue != "" {
		choice := promptSelect(fmt.Sprintf("Use stored value for %s (%s)?", field, currentValue), []string{"Yes", "No"})
		if choice == "Yes" {
			return currentValue
		}
	}
	return PromptInput(prompt, defaultValue, log)
}
