package eosio

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// ErrAlreadyEos is returned when escalation is skipped because the process is already running as 'eos'.
var ErrAlreadyEos = errors.New("already running as eos user")
var ErrEosReexecCompleted = errors.New("re-execution completed, parent exiting")

const (
	TmpPrefix = "/tmp/"
	BashCmd   = "bash"
	SudoCmd   = "sudo"
)

func RequireEosUserOrReexecWithShell(log *zap.Logger, requiresShell bool) error {
	return RequireEosUserOrReexec(log, requiresShell)
}

func RequireEosUserOrReexec(log *zap.Logger, withShell bool) error {
	if log == nil {
		return fmt.Errorf("logger is nil; initialize logger before calling RequireEosUserOrReexec")
	}
	if strings.HasPrefix(os.Args[0], TmpPrefix) {
		return fmt.Errorf("🛑 Cannot escalate with `go run`. Use `go build -o eos`")
	}

	isEos, err := IsRunningAsEos()
	if err != nil {
		return fmt.Errorf("detecting current user failed: %w", err)
	}
	if isEos {
		log.Info("👤 Already running as 'eos' user; skipping sudo escalation")
		return ErrAlreadyEos
	}

	cmd, cmdStr, err := buildSudoCommand(withShell)
	if err != nil {
		return fmt.Errorf("building sudo command failed: %w", err)
	}
	log.Info("🔐 Elevating to 'eos' user", zap.String("command", cmdStr))

	output, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(output))
	if err != nil {
		log.Error("❌ sudo escalation failed",
			zap.Error(err),
			zap.String("command", cmdStr),
			zap.String("output", trimmed),
			zap.String("hint", "check NOPASSWD in sudoers and shell for 'eos' in /etc/passwd"))
		return fmt.Errorf("sudo escalation failed: %w; output: %s", err, trimmed)
	}

	log.Info("✅ Re-execution under 'eos' succeeded; exiting parent")
	return ErrEosReexecCompleted
}

func buildSudoCommand(withShell bool) (*exec.Cmd, string, error) {
	binaryPath, err := os.Executable()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get executable path: %w", err)
	}
	if withShell {
		args := strings.Join(os.Args[1:], " ")
		cmdStr := fmt.Sprintf("%s %s", binaryPath, args)
		return exec.Command(SudoCmd, "-u", shared.EosID, BashCmd, "-c", cmdStr),
			fmt.Sprintf("sudo -u %s bash -c '%s'", shared.EosID, cmdStr), nil
	}
	fullArgs := append([]string{"-u", shared.EosID, binaryPath}, os.Args[1:]...)
	return exec.Command(SudoCmd, fullArgs...),
		fmt.Sprintf("sudo -u %s %s %s", shared.EosID, binaryPath, strings.Join(os.Args[1:], " ")), nil
}

func IsRunningAsEos() (bool, error) {
	u, err := user.Current()
	if err != nil {
		return false, err
	}
	return u.Username == shared.EosID, nil
}

func GetInvokedUsername() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// CanSudoToEos runs a dry-run check: sudo -u eos true.
func CanSudoToEos() (bool, error) {
	cmd := exec.Command(SudoCmd, "-u", shared.EosID, "true")
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("sudo dry-run failed: %w", err)
	}
	return true, nil
}
