// pkg/eosio/eos_user.go

package eosio

import (
	"os"
	"os/exec"
	"os/user"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// RequireEosUserOrReexec ensures the current process is running as the 'eos' system user.
// If not, it attempts to re-execute the current binary using 'sudo -u eos ...'.
// Returns an error if user detection or sudo fails.
func RequireEosUserOrReexec(log *zap.Logger) error {
	currentUser, err := user.Current()
	if err != nil {
		log.Error("Failed to detect current user", zap.Error(err))
		return err
	}

	if currentUser.Username == shared.EosID {
		return nil // Already running as eos
	}

	log.Info("🔐 Elevating to 'eos' user via sudo")
	fullArgs := append([]string{"-u", shared.EosID, os.Args[0]}, os.Args[1:]...)
	cmd := exec.Command("sudo", fullArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Error("sudo failed", zap.Error(err))
		return err
	}

	os.Exit(0) // Successful re-exec; prevent further execution
	return nil
}
