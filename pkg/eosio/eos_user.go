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

const (
	TmpPrefix = "/tmp/"
	BashCmd   = "bash"
	SudoCmd   = "sudo"
)

// RequireEosUserOrReexec ensures the current process runs as the 'eos' system user.
func RequireEosUserOrReexec(log *zap.Logger) error {
	return requireEosUserOrReexecInternal(log, false)
}

// RequireEosUserOrReexecWithShell ensures the process runs as 'eos', optionally using bash -c.
func RequireEosUserOrReexecWithShell(log *zap.Logger, requiresShell bool) error {
	return requireEosUserOrReexecInternal(log, requiresShell)
}

func requireEosUserOrReexecInternal(log *zap.Logger, withShell bool) error {
	if log == nil {
		return fmt.Errorf("logger is nil; initialize logger before calling RequireEosUserOrReexec")
	}
	if strings.HasPrefix(os.Args[0], TmpPrefix) {
		return fmt.Errorf("🛑 Cannot escalate with `go run`. Use `go build -o eos`")
	}
	isEos, err := IsRunningAsEos()
	if err != nil {
		log.Error("Failed to detect current user", zap.Error(err))
		return err
	}
	if isEos {
		log.Debug("Already running as eos user, skipping escalation")
		return nil
	}
	cmd, cmdStr, err := buildSudoCommand(withShell)
	if err != nil {
		log.Error("Failed to build sudo command", zap.Error(err))
		return err
	}
	log.Info("🔐 Elevating to 'eos' user", zap.String("command", cmdStr))

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("sudo escalation failed",
			zap.Error(err),
			zap.ByteString("output", output),
			zap.String("command", cmdStr),
			zap.String("hint", "check sudoers NOPASSWD and eos shell in /etc/passwd"))
		return fmt.Errorf("sudo escalation failed: %w", err)
	}
	log.Info("✅ Re-execution under 'eos' succeeded")
	return fmt.Errorf("re-execution completed, parent exiting")
}

func buildSudoCommand(withShell bool) (*exec.Cmd, string, error) {
	binaryPath, err := os.Executable()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get executable path: %w", err)
	}
	if withShell {
		args := strings.Join(os.Args[1:], " ")
		cmdStr := fmt.Sprintf("%s %s", binaryPath, args)
		return exec.Command(SudoCmd, "-u", shared.EosID, BashCmd, "-c", cmdStr), fmt.Sprintf("sudo -u %s bash -c '%s'", shared.EosID, cmdStr), nil
	}
	fullArgs := append([]string{"-u", shared.EosID, binaryPath}, os.Args[1:]...)
	return exec.Command(SudoCmd, fullArgs...), fmt.Sprintf("sudo -u %s %s %s", shared.EosID, binaryPath, strings.Join(os.Args[1:], " ")), nil
}

// IsRunningAsEos returns true if the current process runs as the 'eos' user.
func IsRunningAsEos() (bool, error) {
	u, err := user.Current()
	if err != nil {
		return false, err
	}
	return u.Username == shared.EosID, nil
}

// GetInvokedUsername returns the current username or an error.
func GetInvokedUsername() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}