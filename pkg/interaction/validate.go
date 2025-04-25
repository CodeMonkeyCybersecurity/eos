// pkg/interaction/validate.go
package interaction

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"

	"go.uber.org/zap"
)

// PromptValidated asks for input until the validator passes.
func PromptValidated(label string, validator func(string) error, log *zap.Logger) string {
	for {
		input := PromptRequired(label, log)
		if err := validator(input); err != nil {
			fmt.Println("❌", err)
			continue
		}
		return input
	}
}

// ---------------- VALIDATORS ---------------- //

// ValidateNonEmpty ensures the input is not empty.
func ValidateNonEmpty(input string, log *zap.Logger) error {
	if strings.TrimSpace(input) == "" {
		return errors.New("input cannot be empty")
	}
	return nil
}

// ValidateUsername ensures the input is a valid UNIX-style username.
func ValidateUsername(input string, log *zap.Logger) error {
	re := regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	if !re.MatchString(input) {
		return errors.New("invalid username (use lowercase letters, digits, underscore, dash)")
	}
	return nil
}

// ValidateEmail uses net/mail to check email format.
func ValidateEmail(input string, log *zap.Logger) error {
	_, err := mail.ParseAddress(input)
	if err != nil {
		return errors.New("invalid email format")
	}
	return nil
}

// ValidateURL ensures a valid absolute URL.
func ValidateURL(input string, log *zap.Logger) error {
	u, err := url.Parse(input)
	if err != nil || !u.IsAbs() {
		return errors.New("invalid URL (must be absolute)")
	}
	return nil
}

// ValidateIP ensures the input is a valid IP address.
func ValidateIP(input string, log *zap.Logger) error {
	if net.ParseIP(input) == nil {
		return errors.New("invalid IP address")
	}
	return nil
}

// ValidateNoShellMeta blocks shell metacharacters.
func ValidateNoShellMeta(input string, log *zap.Logger) error {
	if strings.ContainsAny(input, "`$&|;<>(){}") {
		return errors.New("input contains unsafe shell characters")
	}
	return nil
}
