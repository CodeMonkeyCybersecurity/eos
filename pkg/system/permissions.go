// pkg/system/permissions.go

package system

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

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

func FixEosSudoersFile(log *zap.Logger) error {
	sudoersLine := "eos ALL=(ALL) NOPASSWD: /bin/systemctl"
	cmd := exec.Command("sudo", "bash", "-c", fmt.Sprintf("echo '%s' > /etc/sudoers.d/eos", sudoersLine))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to write sudoers file: %w", err)
	}
	cmd = exec.Command("sudo", "chmod", "440", "/etc/sudoers.d/eos")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set sudoers permissions: %w", err)
	}
	log.Info("✅ Fixed /etc/sudoers.d/eos file and permissions")
	return nil
}

// CanInteractiveSudo checks if the current user can run 'sudo' interactively.
// It tries 'sudo -v' to validate cached credentials or prompt if needed.
func CanInteractiveSudo() bool {
	cmd := exec.Command("sudo", "-v")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Printf("❌ interactive sudo check failed: %v\n", err)
		return false
	}
	return true
}

func CheckSudoersMembership(username string) bool {
	cmd := exec.Command("sudo", "grep", "-r", username, "/etc/sudoers", "/etc/sudoers.d")
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ sudoers membership check failed: %v\n", err)
		return false
	}
	return strings.Contains(string(out), username)
}

func CheckSudoersFile() (bool, error) {
	info, err := os.Stat(shared.EosSudoersPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if info.Mode().Perm() != 0440 {
		return false, fmt.Errorf("wrong permissions: %o", info.Mode().Perm())
	}
	contents, err := os.ReadFile(shared.EosSudoersPath)
	if err != nil {
		return false, err
	}
	if !strings.Contains(string(contents), "eos ALL=(ALL) NOPASSWD: /bin/systemctl") {
		return false, fmt.Errorf("incorrect content")
	}
	return true, nil
}
