// pkg/interaction/validate.go
package interaction

import (
	"errors"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// PromptValidated asks for input until the validator passes.
func PromptValidated(label string, validator func(string) error) string {
	for {
		input := PromptRequired(label)
		if err := validator(input); err != nil {
			fmt.Println("", err)
			continue
		}
		return input
	}
}

// ---------------- VALIDATORS ---------------- //

// ValidateNonEmpty ensures the input is not empty.
func ValidateNonEmpty(input string) error {
	if strings.TrimSpace(input) == "" {
		return errors.New("input cannot be empty")
	}
	return nil
}

// ValidateUsername ensures the input is a valid UNIX-style username.
// DEPRECATED: Use shared.ValidateUsername instead
func ValidateUsername(input string) error {
	return shared.ValidateUsername(input)
}

// ValidateEmail uses net/mail to check email format.
// DEPRECATED: Use shared.ValidateEmail instead  
func ValidateEmail(input string) error {
	return shared.ValidateEmail(input)
}

// ValidateURL ensures a valid absolute URL.
// DEPRECATED: Use shared.ValidateURL instead
func ValidateURL(input string) error {
	return shared.ValidateURL(input)
}

// ValidateIP ensures the input is a valid IP address.
// DEPRECATED: Use shared.ValidateIPAddress instead
func ValidateIP(input string) error {
	return shared.ValidateIPAddress(input)
}

// ValidateNoShellMeta blocks shell metacharacters.
func ValidateNoShellMeta(input string) error {
	if strings.ContainsAny(input, "`$&|;<>(){}") {
		return errors.New("input contains unsafe shell characters")
	}
	return nil
}
