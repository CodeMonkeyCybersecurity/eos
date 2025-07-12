// Package k3s provides utilities for managing K3s installations
package k3s

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UninstallScripts defines the K3s uninstall scripts and their roles
var UninstallScripts = map[string]string{
	"server": "/usr/local/bin/k3s-uninstall.sh",
	"agent":  "/usr/local/bin/k3s-agent-uninstall.sh",
	"kill":   "/usr/local/bin/k3s-killall.sh",
}

// Uninstall removes K3s from the system following the Assess → Intervene → Evaluate pattern.
// It detects whether this machine is running a K3s server or agent and removes it
// by running the appropriate uninstall scripts in the correct order.
func Uninstall(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check which scripts are present
	logger.Info("Assessing K3s installation")

	var scriptsFound []string
	for role, path := range UninstallScripts {
		if eos_unix.Exists(path) {
			logger.Debug("Found uninstall script",
				zap.String("role", role),
				zap.String("path", path))
			scriptsFound = append(scriptsFound, role)
		}
	}

	if len(scriptsFound) == 0 {
		logger.Info("No K3s uninstall scripts found - K3s is not installed")
		return nil
	}

	// INTERVENE - Run uninstall scripts
	logger.Info("Running K3s uninstall process",
		zap.Strings("scripts_found", scriptsFound))

	var ranAny bool
	for role, path := range UninstallScripts {
		if eos_unix.Exists(path) {
			logger.Info("▶ Running uninstall script",
				zap.String("role", role),
				zap.String("path", path))

			err := execute.RunSimple(rc.Ctx, path)
			if err != nil {
				logger.Error("❌ Script execution failed",
					zap.String("role", role),
					zap.Error(err))
				return fmt.Errorf("failed to run %s script: %w", role, err)
			}

			logger.Info(" Successfully ran uninstall script",
				zap.String("role", role))
			ranAny = true
		}
	}

	// EVALUATE - Verify uninstallation
	if !ranAny {
		logger.Warn("No uninstall scripts were executed - this shouldn't happen")
		return fmt.Errorf("found scripts but none were executed")
	}

	// Check if K3s binary still exists
	if eos_unix.Exists("/usr/local/bin/k3s") {
		logger.Warn("K3s binary still exists after uninstall")
	} else {
		logger.Info("K3s binary successfully removed")
	}

	// Check if K3s data directory still exists
	if eos_unix.Exists("/var/lib/rancher/k3s") {
		logger.Info("K3s data directory still exists - may contain persistent data")
	}

	logger.Info("K3s uninstallation completed successfully")
	return nil
}
