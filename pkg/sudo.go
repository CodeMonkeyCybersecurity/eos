// pkg/utils/sudo.go
package utils

import (
	"os/exec"
)

// CheckSudo checks if the current user has sudo privileges
func CheckSudo() bool {
	cmd := exec.Command("sudo", "-n", "true") // Non-interactive sudo check
	err := cmd.Run()
	return err == nil
}
