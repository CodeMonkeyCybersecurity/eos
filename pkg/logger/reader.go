package logger

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

const journalSinceDefault = "today"

// ReadLogFile returns the contents of a given log file.
func ReadLogFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read log file %s: %w", path, err)
	}
	return string(data), nil
}

// TryReadLogFile safely reads a log file after validating that it exists and is not a directory.
func TryReadLogFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		zap.L().Warn("Invalid log file path", zap.String("path", path))
		return "", fmt.Errorf("invalid log file path: %s", path)
	}
	return ReadLogFile(path)
}

// TryJournalctl fetches recent EOS logs using journalctl, returning the output.
func TryJournalctl() (string, error) {
	cmd := exec.Command("journalctl", "-u", shared.EosID, "--no-pager", "--since", journalSinceDefault)
	out, err := cmd.CombinedOutput()
	if err != nil {
		zap.L().Warn("Failed to query journalctl", zap.Error(err))
		return "", fmt.Errorf("could not query journalctl: %w", err)
	}
	return string(out), nil
}
