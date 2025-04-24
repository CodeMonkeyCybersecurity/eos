/* pkg/platform/eos_user.go */

package platform

import (
	"fmt"
	"os/exec"
	"os/user"
)

// UserExists returns true if a local system user with the given name exists.
func UserExists(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
}

//
// EnsureUserExists checks for a system user and creates it if missing.
//
func EnsureSystemUser(name string) error {
	if UserExists(name) {
		return nil
	}

	cmd := exec.Command("useradd", "--system", "--create-home", "--shell", "/usr/sbin/nologin", "--user-group", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create user %q: %v\n%s", name, err, string(out))
	}

	return nil
}