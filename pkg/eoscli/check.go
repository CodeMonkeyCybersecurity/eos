// pkg/eos/check.go

package eoscli

import (
	"os/user"
)

// EosUserExists returns true if a local system user named "eos" exists
func EosUserExists() bool {
	_, err := user.Lookup("eos")
	return err == nil
}
