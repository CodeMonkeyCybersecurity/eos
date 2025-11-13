// pkg/system/disk.go
//
// Disk space checking utilities - pure business logic

package system

import (
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckDiskSpace checks available disk space for the specified paths
// Returns df output for logging purposes (doesn't parse, just checks availability)
func CheckDiskSpace(rc *eos_io.RuntimeContext, paths ...string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	args := append([]string{"-h"}, paths...)
	dfCmd := exec.Command("df", args...)
	output, err := dfCmd.Output()
	if err != nil {
		logger.Warn("Could not check disk space", zap.Error(err))
		return "", nil // Non-fatal
	}

	outputStr := strings.TrimSpace(string(output))
	logger.Debug("Disk space check", zap.String("df_output", outputStr))

	return outputStr, nil
}
