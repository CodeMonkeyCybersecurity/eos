// pkg/ceph/configuration.go
package ceph

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// CheckConfiguration validates Ceph configuration files
func CheckConfiguration(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	logger.Info("Checking Ceph configuration...")

	// Check ceph.conf
	configPath := "/etc/ceph/ceph.conf"
	cmd := exec.Command("cat", configPath)
	output, err := cmd.Output()
	if err != nil {
		logger.Error("❌ Cannot read " + configPath)
		return DiagnosticResult{
			CheckName: "Configuration",
			Passed:    false,
			Error:     fmt.Errorf("config file not found: %w", err),
		}
	}

	logger.Info("✓ Configuration file exists: " + configPath)
	if verbose {
		logger.Info("Configuration contents:")
		for _, line := range strings.Split(string(output), "\n") {
			if strings.TrimSpace(line) != "" {
				logger.Info("  " + line)
			}
		}
	}

	// Check for keyrings
	logger.Info("Checking keyrings...")
	cmd = exec.Command("ls", "-lah", "/etc/ceph/")
	if output, err := cmd.Output(); err == nil {
		keyringFound := false
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, ".keyring") {
				keyringFound = true
				logger.Info("  " + line)
			}
		}

		if !keyringFound {
			logger.Warn("  No keyring files found in /etc/ceph/")
			logger.Info("  → Authentication may fail")
			return DiagnosticResult{
				CheckName: "Configuration",
				Passed:    false,
				Error:     fmt.Errorf("no keyrings found"),
			}
		}
	}

	// Validate config syntax using ceph-conf if available
	cmd = exec.Command("ceph-conf", "--show-config")
	if output, err := cmd.Output(); err == nil {
		logger.Info("✓ Configuration syntax is valid")
		if verbose {
			logger.Info("Parsed configuration:")
			for _, line := range strings.Split(string(output), "\n")[:20] {
				if strings.TrimSpace(line) != "" {
					logger.Info("  " + line)
				}
			}
		}
	}

	return DiagnosticResult{
		CheckName: "Configuration",
		Passed:    true,
	}
}
