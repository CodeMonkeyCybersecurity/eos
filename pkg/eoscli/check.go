// pkg/eos/check.go

package eoscli

import (
	"os/user"
)

// EosUserExists returns true if a local system user named "eos" exists
func eosUserExists() bool {
	_, err := user.Lookup("eos")
	return err == nil
}

// IsEosUser returns true if the local system user "eos" exists.
// Useful for enforcing permission checks across CLI operations.
func isEosUser() bool {
	return eosUserExists()
}
