// pkg/ceph/storage.go
package ceph

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// CheckStorage checks storage layer (OSD data directories, devices)
func CheckStorage(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	logger.Info("Checking storage layer...")

	// Check OSD data directories
	cmd := exec.Command("ls", "-lah", "/var/lib/ceph/osd/")
	output, err := cmd.Output()
	if err != nil {
		logger.Warn("  Cannot access /var/lib/ceph/osd/")
		return DiagnosticResult{
			CheckName: "Storage",
			Passed:    false,
			Error:     fmt.Errorf("osd directory not accessible: %w", err),
		}
	}

	lines := strings.Split(string(output), "\n")
	osdCount := 0
	for _, line := range lines {
		if strings.Contains(line, "ceph-") {
			osdCount++
			if verbose {
				logger.Info("  " + line)
			}
		}
	}

	if osdCount == 0 {
		logger.Warn("  No OSD directories found")
		logger.Info("  → OSDs may not be configured")
	} else {
		logger.Info(fmt.Sprintf("Found %d OSD directories", osdCount))
	}

	// Check disk space on Ceph directories
	cmd = exec.Command("df", "-h", "/var/lib/ceph")
	if output, err := cmd.Output(); err == nil {
		logger.Info("Disk space for /var/lib/ceph:")
		for _, line := range strings.Split(string(output), "\n") {
			if strings.TrimSpace(line) != "" {
				logger.Info("  " + line)
			}
		}
	}

	// Check MON data directories
	cmd = exec.Command("ls", "-lah", "/var/lib/ceph/mon/")
	if output, err := cmd.Output(); err == nil {
		monCount := 0
		lines = strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "ceph-") {
				monCount++
				if verbose {
					logger.Info("  " + line)
				}
			}
		}

		if monCount > 0 {
			logger.Info(fmt.Sprintf("Found %d MON directories", monCount))
		}
	}

	return DiagnosticResult{
		CheckName: "Storage",
		Passed:    true,
	}
}
