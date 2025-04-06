// pkg/hera/check.go
package hera

import (
	"os/user"
)

// HeraUserExists returns true if a local system user named "hera" exists
func HeraUserExists() bool {
	_, err := user.Lookup("hera")
	return err == nil
}
