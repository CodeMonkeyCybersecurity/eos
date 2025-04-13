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

/* EnforceSecretsAccess blocks --show-secrets unless run as root */
func EnforceSecretsAccess(log *zap.Logger, show bool) bool {
	if show && !IsPrivilegedUser() {
		log.Warn("Non-root user attempted to use --show-secrets")
		fmt.Fprintln(os.Stderr, "🚫 --show-secrets can only be used by root or sudo.")
		return false
	}
	return true
}

func RequireRoot(log *zap.Logger) {
	if !IsPrivilegedUser() {
		log.Error("Root access required")
		fmt.Fprintln(os.Stderr, "❌ This command must be run as root (try sudo).")
		os.Exit(1)
	}
}

func FailIfPermissionDenied(log *zap.Logger, action, path string, err error) {
	if os.IsPermission(err) {
		log.Error(fmt.Sprintf("❌ %s failed due to permissions", action),
			zap.String("path", path),
			zap.Error(err),
		)
		fmt.Fprintf(os.Stderr, "\n🔒 %s requires elevated privileges.\n", action)
		fmt.Fprintln(os.Stderr, "👉 Try rerunning the command with sudo:")
		fmt.Fprintf(os.Stderr, "   sudo eos %s\n\n", os.Args[1:])
		os.Exit(1)
	}
}
