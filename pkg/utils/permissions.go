// pkg/utils/permissions.go

package utils

import (
	"fmt"
	"os"
	"os/exec"

	"go.uber.org/zap"
)

//
//---------------------------- PERMISSIONS ---------------------------- //
//

// CheckSudo checks if the current user has sudo privileges
func CheckSudo() bool {
	cmd := exec.Command("sudo", "-n", "true")
	err := cmd.Run()
	return err != nil
}

// IsPrivilegedUser returns true if the current user is UID 0 (root)
func IsPrivilegedUser() bool {
	return os.Geteuid() == 0
}

func EnforceSecretsAccess(log *zap.Logger, show bool) bool {
	if show && !IsPrivilegedUser() {
		log.Warn("Non-root user attempted to use --show-secrets")
		fmt.Println("🚫 --show-secrets can only be used by root or sudo.")
		return false
	}
	return true
}
