// pkg/eosio/eos_user.go

package eosio

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// RequireEosUserOrReexec ensures the current process is running as the 'eos' system user.
// If not, it attempts to re-execute the current binary using 'sudo -u eos ...'.
func RequireEosUserOrReexec(log *zap.Logger) error {
	if log == nil {
		return fmt.Errorf("logger not initialized before RequireEosUserOrReexec")
	}

	if strings.HasPrefix(os.Args[0], "/tmp/") {
		log.Error("🛑 Cannot escalate with `go run`. Use `go build -o eos`.")
		return fmt.Errorf("binary path %s is not suitable for sudo", os.Args[0])
	}

	currentUser, err := user.Current()
	if err != nil {
		log.Error("Failed to detect current user", zap.Error(err))
		return err
	}

	if currentUser.Username == shared.EosID {
		return nil // Already running as eos
	}

	log.Info("🔐 Elevating to 'eos' user via sudo")
	binaryPath, err := os.Executable()
	if err != nil {
		log.Error("Failed to get current binary path", zap.Error(err))
		return err
	}

	fullArgs := append([]string{"-u", shared.EosID, binaryPath}, os.Args[1:]...)
	cmd := exec.Command("sudo", fullArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Error("sudo failed", zap.Error(err))
		return err
	}

	os.Exit(0) // Successful re-exec
	return nil
}

func RequireEosUserOrReexecWithShell(log *zap.Logger, requiresShell bool) error {
	if requiresShell {
		return RequireEosUserOrReexecWithBashC(log)
	}
	return RequireEosUserOrReexec(log)
}

// RequireEosUserOrReexecWithBashC elevates the current process as 'eos' user
// and wraps the command in a bash -c shell.
func RequireEosUserOrReexecWithBashC(log *zap.Logger) error {
	if log == nil {
		return fmt.Errorf("logger not initialized before RequireEosUserOrReexecWithBashC")
	}

	if strings.HasPrefix(os.Args[0], "/tmp/") {
		log.Error("🛑 Cannot escalate with `go run`. Use `go build -o eos`.")
		return fmt.Errorf("binary path %s is not suitable for sudo", os.Args[0])
	}

	currentUser, err := user.Current()
	if err != nil {
		log.Error("Failed to detect current user", zap.Error(err))
		return err
	}

	if currentUser.Username == shared.EosID {
		return nil // Already running as eos
	}

	log.Info("🔐 Elevating to 'eos' user via sudo bash -c")
	binaryPath, err := os.Executable()
	if err != nil {
		log.Error("Failed to get current binary path", zap.Error(err))
		return err
	}

	// Reconstruct command string
	args := strings.Join(os.Args[1:], " ")
	fullCommand := fmt.Sprintf("%s %s", binaryPath, args)

	// Build sudo command with bash -c
	cmd := exec.Command("sudo", "-u", shared.EosID, "bash", "-c", fullCommand)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Error("sudo bash -c failed", zap.Error(err))
		return err
	}

	os.Exit(0) // Successful re-exec
	return nil
}
