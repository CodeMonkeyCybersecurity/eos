/* pkg/interaction/remember.go */

package interaction

import "fmt"

// FallbackOption is already defined in your fallback package, so we assume that's available.

// RememberValue prompts the user to either reuse an existing value or enter a new one.
// It returns the chosen value.
func rememberValue(field, prompt, defaultValue, currentValue string) string {
	if currentValue != "" {
		choice := promptSelect(fmt.Sprintf("Use stored value for %s (%s)?", field, currentValue), []string{"Yes", "No"})
		if choice == "Yes" {
			return currentValue
		}
	}
	return promptInput(prompt, defaultValue)
}
