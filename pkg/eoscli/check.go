// pkg/eoscli/check.go
package eoscli

import (
	"fmt"
	"os/exec"
	"os/user"
)

// ensureEOSSystemUser creates a system user called "eos" if it doesn't exist.
func ensureEOSSystemUser() error {
	if eosUserExists() {
		fmt.Println("✅ eos system user already exists")
		return nil
	}

	fmt.Println("👤 Creating eos system user...")
	cmd := exec.Command("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "eos")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create eos user: %v\n%s", err, string(out))
	}

	fmt.Println("✅ eos system user created")
	return nil
}

// eosUserExists returns true if the local system user "eos" exists.
func eosUserExists() bool {
	_, err := user.Lookup("eos")
	return err == nil
}