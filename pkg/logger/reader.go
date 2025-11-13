package logger

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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
func TryReadLogFile(rc *eos_io.RuntimeContext, path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		otelzap.Ctx(rc.Ctx).Warn("Invalid log file path", zap.String("path", path))
		return "", fmt.Errorf("invalid log file path: %s", path)
	}
	return ReadLogFile(path)
}

// TryJournalctl fetches recent Eos logs using journalctl, returning the output.
func TryJournalctl(rc *eos_io.RuntimeContext) (string, error) {
	cmd := exec.Command("journalctl", "-u", shared.EosID, "--no-pager", "--since", journalSinceDefault)
	out, err := cmd.CombinedOutput()
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Failed to query journalctl", zap.Error(err))
		return "", fmt.Errorf("could not query journalctl: %w", err)
	}
	return string(out), nil
}
