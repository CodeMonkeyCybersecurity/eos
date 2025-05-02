// pkg/eosio/eos_user.go

package eosio

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoserr"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// RequireEosUserOrReexec ensures the current process is running as the 'eos' system user.
// If not, it re-executes the current binary using 'sudo -u eos bash -c ...'.
func RequireEosUserOrReexec(log *zap.Logger) error {
	if log == nil {
		log = logger.L()
		if log == nil {
			log = logger.NewFallbackLogger()
		}
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

	// Build the full command string: `eos <args...>`
	escapedArgs := []string{binaryPath}
	escapedArgs = append(escapedArgs, os.Args[1:]...)
	fullCommand := strings.Join(escapedArgs, " ")

	// sudo -u eos bash -c '<command>'
	cmd := exec.Command("sudo", "-u", shared.EosID, "bash", "-c", fullCommand)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Error("sudo -u eos bash -c failed", zap.Error(err))
		return err
	}

	// Instead of os.Exit(0), return sentinel error
	return eoserr.ErrReexecCompleted
}
