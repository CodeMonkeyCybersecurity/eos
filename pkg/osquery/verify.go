// pkg/osquery/verify.go

package osquery

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// verifyLinuxInstallation verifies osquery installation on Linux
func verifyLinuxInstallation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔍 Verifying osquery installation on Linux")

	// Check osqueryi version
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "osqueryi",
		Args:    []string{"--version"},
	})
	if err != nil {
		logger.Error("❌ osqueryi not found or not working",
			zap.Error(err))
		return fmt.Errorf("osqueryi verification failed: %w", err)
	}

	// Clean up the version output and extract version number
	version := strings.TrimSpace(output)
	if version != "" {
		// Extract version from "osqueryi version X.X.X" format
		parts := strings.Fields(version)
		if len(parts) >= 3 && parts[1] == "version" {
			version = parts[2]
		}
	}
	
	logger.Info("✅ osquery verified",
		zap.String("version", version))

	// Check if config file exists
	paths := GetOsqueryPaths()
	if _, err := os.Stat(paths.ConfigPath); err != nil {
		logger.Warn("⚠️ Configuration file not found",
			zap.String("path", paths.ConfigPath),
			zap.Error(err))
	} else {
		logger.Info("✅ Configuration file exists",
			zap.String("path", paths.ConfigPath))
	}

	// Check service status
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "osqueryd"},
	})
	if err != nil || strings.TrimSpace(output) != "active" {
		logger.Warn("⚠️ osquery service is not active",
			zap.String("status", strings.TrimSpace(output)),
			zap.Error(err))
	} else {
		logger.Info("✅ osquery service is active")
	}

	// Check if osquery is enabled
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-enabled", "osqueryd"},
	})
	if err != nil || strings.TrimSpace(output) != "enabled" {
		logger.Warn("⚠️ osquery service is not enabled",
			zap.String("status", strings.TrimSpace(output)),
			zap.Error(err))
	} else {
		logger.Info("✅ osquery service is enabled")
	}

	return nil
}

// RunOsqueryQuery executes a query using osqueryi
func RunOsqueryQuery(rc *eos_io.RuntimeContext, query string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔍 Running osquery query",
		zap.String("query", query))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "osqueryi",
		Args:    []string{"--json", query},
	})
	if err != nil {
		logger.Error("❌ Failed to run osquery query",
			zap.String("query", query),
			zap.Error(err))
		return "", fmt.Errorf("run osquery query: %w", err)
	}

	return output, nil
}

// GetOsqueryStatus returns the current status of osquery service
func GetOsqueryStatus(rc *eos_io.RuntimeContext) (string, error) {
	switch platform.GetOSPlatform() {
	case "linux":
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"status", "osqueryd"},
		})
		return output, err
		
	case "macos":
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "sudo",
			Args:    []string{"launchctl", "list", "com.facebook.osqueryd"},
		})
		return output, err
		
	case "windows":
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "sc",
			Args:    []string{"query", "osqueryd"},
		})
		return output, err
		
	default:
		return "", fmt.Errorf("unsupported platform")
	}
}