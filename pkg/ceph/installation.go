// pkg/ceph/installation.go
package ceph

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// CheckInstallation checks what Ceph packages/components are installed
func CheckInstallation(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	logger.Info("Checking Ceph installation...")

	// Check for Debian/Ubuntu packages
	cmd := exec.Command("dpkg", "-l")
	output, err := cmd.Output()
	if err != nil {
		// Try RPM-based systems
		cmd = exec.Command("rpm", "-qa")
		output, err = cmd.Output()
		if err != nil {
			return DiagnosticResult{
				CheckName: "Installation",
				Passed:    false,
				Error:     fmt.Errorf("cannot query package manager: %w", err),
			}
		}
	}

	cephPackages := []string{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "ceph") {
			cephPackages = append(cephPackages, strings.TrimSpace(line))
		}
	}

	if len(cephPackages) == 0 {
		logger.Warn("⚠️  No Ceph packages found")
		return DiagnosticResult{
			CheckName: "Installation",
			Passed:    false,
			Error:     fmt.Errorf("ceph not installed"),
		}
	}

	logger.Info(fmt.Sprintf("Found %d Ceph packages", len(cephPackages)))
	if verbose {
		for _, pkg := range cephPackages {
			logger.Info("  " + pkg)
		}
	}

	// Check Ceph version
	cmd = exec.Command("ceph", "--version")
	if output, err := cmd.Output(); err == nil {
		logger.Info("Ceph version: " + strings.TrimSpace(string(output)))
	}

	// Check user/group
	cmd = exec.Command("id", "ceph")
	if output, err := cmd.Output(); err == nil {
		logger.Info("Ceph user: " + strings.TrimSpace(string(output)))
	} else {
		logger.Warn("⚠️  Ceph user not found")
		// Check UID 64045 (common Ceph UID)
		cmd = exec.Command("id", "64045")
		if output, err := cmd.Output(); err == nil {
			logger.Info("UID 64045 exists: " + strings.TrimSpace(string(output)))
		}
	}

	return DiagnosticResult{
		CheckName: "Installation",
		Passed:    true,
	}
}
