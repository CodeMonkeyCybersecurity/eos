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
// Returns an error if user detection or sudo fails.
func RequireEosUserOrReexec() error {
	if strings.HasPrefix(os.Args[0], "/tmp/") {
		zap.L().Error("🛑 Cannot escalate with `go run`. Use `go build -o eos`.")
		return fmt.Errorf("binary path %s is not suitable for sudo", os.Args[0])
	}

	currentUser, err := user.Current()
	if err != nil {
		zap.L().Error("Failed to detect current user", zap.Error(err))
		return err
	}

	if currentUser.Username == shared.EosID {
		zap.L().Info("👤 Already running as 'eos' user; no escalation needed")
		return nil
	}

	binaryPath, err := os.Executable()
	if err != nil {
		zap.L().Error("Failed to get current binary path", zap.Error(err))
		return err
	}
	fullArgs := append([]string{"-u", shared.EosID, binaryPath}, os.Args[1:]...)
	cmd := exec.Command("sudo", fullArgs...)
	var stdoutBuf, stderrBuf strings.Builder
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	cmdStr := fmt.Sprintf("sudo -u %s %s %s", shared.EosID, binaryPath, strings.Join(os.Args[1:], " "))
	zap.L().Info("🔐 Preparing sudo escalation",
		zap.String("cmd", cmdStr),
		zap.Strings("args", cmd.Args),
		zap.String("PATH", os.Getenv("PATH")),
		zap.String("SHELL", os.Getenv("SHELL")),
	)

	err = cmd.Run()
	zap.L().Info("🔐 sudo stdout", zap.String("stdout", stdoutBuf.String()))
	zap.L().Info("🔐 sudo stderr", zap.String("stderr", stderrBuf.String()))

	if err != nil {
		zap.L().Error("❌ sudo failed",
			zap.Error(err),
			zap.String("cmd", cmdStr),
			zap.String("stdout", stdoutBuf.String()),
			zap.String("stderr", stderrBuf.String()),
		)
		return err
	}

	zap.L().Info("✅ sudo escalation succeeded; exiting parent process")
	os.Exit(0) // Successful re-exec; prevent further execution
	return nil
}
