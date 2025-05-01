// pkg/utils/permissions.go

package utils

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
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

func IsPrivilegedUser(log *zap.Logger) bool {
	current, err := user.Current()
	if err != nil {
		log.Warn("🧪 Could not determine current user", zap.Error(err))
		return os.Geteuid() == 0
	}
	return current.Username == shared.EosUser || os.Geteuid() == 0
}

/* EnforceSecretsAccess blocks --show-secrets unless run as root */
func EnforceSecretsAccess(log *zap.Logger, show bool) bool {
	if show && !IsPrivilegedUser(log) {
		log.Warn("Non-root user attempted to use --show-secrets")
		fmt.Fprintln(os.Stderr, "🚫 --show-secrets can only be used by root or sudo.")
		return false
	}
	return true
}

func RequireRoot(log *zap.Logger) {
	if !IsPrivilegedUser(log) {
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
