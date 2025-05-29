/* pkg/interaction/remember.go */

package interaction

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// FallbackOption is already defined in your fallback package, so we assume that's available.

// RememberValue prompts the user to either reuse an existing value or enter a new one.
// It returns the chosen value.
func Remember(rc *eos_io.RuntimeContext, field, prompt, defaultValue, currentValue string) string {
	if currentValue != "" {
		choice := PromptSelect(rc.Ctx, fmt.Sprintf("Use stored value for %s (%s)?", field, currentValue), []string{"Yes", "No"})
		if choice == "Yes" {
			return currentValue
		}
	}
	return PromptInput(rc.Ctx, prompt, defaultValue)
}
