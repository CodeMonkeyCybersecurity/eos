// pkg/unix/permissions.go

package eos_unix

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

//
//---------------------------- PERMISSIONS ---------------------------- //
//

// CheckSudo checks if the current user has sudo privileges
func CheckSudo() bool {
	cmd := exec.Command("sudo", "-n", "true")
	err := cmd.Run()
	return err == nil // Fixed: return true if command succeeds
}

func IsPrivilegedUser(ctx context.Context) bool {
	current, err := user.Current()
	if err != nil {
		otelzap.Ctx(ctx).Warn(" Could not determine current user", zap.Error(err))
		return os.Geteuid() == 0
	}
	return current.Username == shared.EosID || os.Geteuid() == 0
}

/* EnforceSecretsAccess blocks --show-secrets unless run as root */
func EnforceSecretsAccess(ctx context.Context, show bool) bool {
	if show && !IsPrivilegedUser(ctx) {
		otelzap.Ctx(ctx).Warn("Non-root user attempted to use --show-secrets")
		fmt.Fprintln(os.Stderr, "🚫 --show-secrets can only be used by root or sudo.")
		return false
	}
	return true
}

func RequireRoot(ctx context.Context) {
	if !IsPrivilegedUser(ctx) {
		zap.L().Error("Root access required")
		fmt.Fprintln(os.Stderr, " This command must be run as root (try sudo).")
		os.Exit(1)
	}
}

// RequireRootInteractive ensures the user is root or has sudo, and prompts if needed.
func RequireRootInteractive() error {
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("cannot determine current user: %w", err)
	}
	if currentUser.Uid == "0" {
		return nil // already root
	}
	fmt.Println("Bootstrap requires root privileges. You may be prompted for your password.")
	cmd := exec.Command("sudo", "-v")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to acquire sudo privileges: %w", err)
	}
	return nil
}

func FailIfPermissionDenied(ctx context.Context, action, path string, err error) {
	if os.IsPermission(err) {
		otelzap.Ctx(ctx).Error(fmt.Sprintf(" %s failed due to permissions", action),
			zap.String("path", path),
			zap.Error(err),
		)
		fmt.Fprintf(os.Stderr, "\n %s requires elevated privileges.\n", action)
		fmt.Fprintln(os.Stderr, " Try rerunning the command with sudo:")
		fmt.Fprintf(os.Stderr, "   sudo eos %s\n\n", os.Args[1:])
		os.Exit(1)
	}
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
		fmt.Printf(" interactive sudo check failed: %v\n", err)
		return false
	}
	return true
}

func CheckSudoersMembership(username string) bool {
	// Use sudo to safely check sudoers membership
	cmd := exec.Command("sudo", "grep", "-r", username, "/etc/sudoers", "/etc/sudoers.d")
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf(" sudoers membership check failed: %v\n", err)
		return false
	}
	return strings.Contains(string(out), username)
}
