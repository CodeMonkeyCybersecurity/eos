/* pkg/eoscli/check.go */

package eoscli

import (
	"fmt"
	"os/exec"
	"os/user"

	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
)

// ensureEosUser ensures the 'eos' user exists and has the correct attributes.
func ensureEosUser() error {
	const eosUsername = "eos"

	if !platform.UserExists(eosUsername) {
		fmt.Println("👤 eos user not found, creating...")
		if err := platform.EnsureSystemUserExists(eosUsername); err != nil {
			return fmt.Errorf("failed to create eos user: %w", err)
		}
		fmt.Println("✅ eos user created successfully")
	} else {
		fmt.Println("✅ eos user exists")

		u, err := user.Lookup(eosUsername)
		if err != nil {
			return fmt.Errorf("failed to lookup user '%s': %w", eosUsername, err)
		}

		// Basic sanity check on name
		if u.Username != eosUsername {
			return fmt.Errorf("⚠️ eos username mismatch '%s': %w", eosUsername, err)
		}

		// Check shell is nologin
		shell, err := getUserShell(eosUsername)
		if err != nil {
			return err
		}
		if !strings.Contains(shell, "nologin") {
			return fmt.Errorf("user '%s' has shell access: %s (expected /usr/sbin/nologin)", eosUsername, shell)
		}

		fmt.Println("✅ eos user has no shell access")
		fmt.Println("✅ eos user validation complete")
		return nil
	}
	return nil
}

func getUserShell(username string) (string, error) {
	cmd := exec.Command("getent", "passwd", username)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get shell for user '%s': %w", username, err)
	}
	parts := strings.Split(string(out), ":")
	if len(parts) < 7 {
		return "", fmt.Errorf("unexpected passwd format for user '%s'", username)
	}
	return strings.TrimSpace(parts[6]), nil
}
