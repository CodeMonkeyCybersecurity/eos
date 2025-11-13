package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// getConsulBinaryPath returns the path to the Consul binary
// NOTE: Duplicates consul.GetConsulBinaryPath() to avoid circular import
// (pkg/consul/service cannot import parent pkg/consul)
func getConsulBinaryPath() string {
	// Check common locations
	paths := []string{
		"/usr/local/bin/consul", // Manual install (preferred)
		"/usr/bin/consul",       // APT package install
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Fallback to PATH lookup
	if path, err := exec.LookPath("consul"); err == nil {
		return path
	}

	return "/usr/local/bin/consul" // Default fallback
}

// validateConsulConfig validates the Consul configuration before starting the service
func validateConsulConfig(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Validating Consul configuration before service start")

	// Check if Consul binary exists
	consulBinary := getConsulBinaryPath()
	if _, err := os.Stat(consulBinary); err != nil {
		return fmt.Errorf("consul binary not found at %s: %w", consulBinary, err)
	}

	// Check if config directory exists
	configDir := "/etc/consul.d"
	if _, err := os.Stat(configDir); err != nil {
		return fmt.Errorf("consul config directory not found at %s: %w", configDir, err)
	}

	// Check if main config file exists
	mainConfigFile := "/etc/consul.d/consul.hcl"
	if _, err := os.Stat(mainConfigFile); err != nil {
		log.Warn("Main consul config file not found",
			zap.String("config_file", mainConfigFile),
			zap.Error(err))
		// Don't fail here, there might be other config files
	}

	// Check if consul user exists (required for service to start)
	userCheckCmd := execute.Options{
		Command: "id",
		Args:    []string{"consul"},
		Capture: true,
	}

	if _, err := execute.Run(rc.Ctx, userCheckCmd); err != nil {
		log.Error("Consul user does not exist", zap.Error(err))
		return fmt.Errorf("consul user does not exist: %w", err)
	}

	// Validate configuration using consul validate command
	validateCmd := execute.Options{
		Command: consulBinary,
		Args:    []string{"validate", configDir},
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, validateCmd)
	if err != nil {
		log.Error("Consul configuration validation failed",
			zap.String("config_dir", configDir),
			zap.String("validation_output", output),
			zap.Error(err))
		return fmt.Errorf("consul configuration validation failed: %w", err)
	}

	log.Info("Consul configuration validation passed",
		zap.String("config_dir", configDir),
		zap.String("validation_output", output))

	return nil
}

// Start enables and starts the Consul service
// Migrated from cmd/create/consul.go startConsulService
func Start(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check service state
	log.Info("Assessing Consul service state")

	// Validate Consul configuration before attempting to start
	if err := validateConsulConfig(rc); err != nil {
		return fmt.Errorf("consul configuration validation failed: %w", err)
	}

	// Check if service exists
	checkCmd := execute.Options{
		Command: "systemctl",
		Args:    []string{"list-unit-files", "consul.service"},
		Capture: true, // Ensure we capture the output
	}
	output, err := execute.Run(rc.Ctx, checkCmd)

	log.Debug("systemctl list-unit-files output",
		zap.String("command", "systemctl list-unit-files consul.service"),
		zap.String("output", output),
		zap.Error(err))

	if err != nil {
		log.Error("Failed to check service existence",
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("failed to check service existence: %w", err)
	}

	if !strings.Contains(output, "consul.service") {
		log.Error("consul.service not found in systemd output",
			zap.String("expected", "consul.service"),
			zap.String("actual_output", output),
			zap.Int("output_length", len(output)))
		return fmt.Errorf("consul.service not found in systemd")
	}

	log.Info("consul.service found in systemd", zap.String("output", output))

	// INTERVENE - Enable and start service
	log.Info("Starting Consul service")

	steps := []execute.Options{
		{Command: "systemctl", Args: []string{"enable", "consul"}},
		{Command: "systemctl", Args: []string{"start", "consul"}, Timeout: 90000}, // 90 second timeout
	}

	for _, step := range steps {
		cmdStr := strings.Join(append([]string{step.Command}, step.Args...), " ")
		log.Info("Executing systemctl command", zap.String("command", cmdStr))

		if err := execute.RunSimple(rc.Ctx, step.Command, step.Args...); err != nil {
			log.Error("systemctl command failed",
				zap.String("command", cmdStr),
				zap.Error(err))

			// If this is a start command that failed, get systemd logs for better error reporting
			if step.Command == "systemctl" && len(step.Args) > 0 && step.Args[0] == "start" {
				serviceName := "consul"
				if len(step.Args) > 1 {
					serviceName = step.Args[1]
				}

				log.Error("Service failed to start, checking systemd logs",
					zap.String("service", serviceName))

				// Get recent systemd logs for this service
				logsCmd := execute.Options{
					Command: "journalctl",
					Args:    []string{"-u", serviceName + ".service", "--no-pager", "--lines=20", "--since=1min ago"},
					Capture: true,
				}

				logsOutput, logsErr := execute.Run(rc.Ctx, logsCmd)
				if logsErr != nil {
					log.Warn("Failed to retrieve systemd logs",
						zap.String("service", serviceName),
						zap.Error(logsErr))
				} else {
					log.Error("Systemd service logs",
						zap.String("service", serviceName),
						zap.String("logs", logsOutput))
				}

				// Also check service status for more details
				statusCmd := execute.Options{
					Command: "systemctl",
					Args:    []string{"status", serviceName},
					Capture: true,
				}

				statusOutput, statusErr := execute.Run(rc.Ctx, statusCmd)
				if statusErr != nil {
					log.Warn("Failed to retrieve service status",
						zap.String("service", serviceName),
						zap.Error(statusErr))
				} else {
					log.Error("Service status details",
						zap.String("service", serviceName),
						zap.String("status", statusOutput))
				}
			}

			return fmt.Errorf("%s failed: %w", cmdStr, err)
		}

		log.Info("systemctl command succeeded", zap.String("command", cmdStr))
	}

	// EVALUATE - Verify service is running
	log.Info("Evaluating Consul service status")

	statusCmd := execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "consul"},
		Capture: true, // Ensure we capture the output
	}
	statusOutput, err := execute.Run(rc.Ctx, statusCmd)

	log.Debug("systemctl is-active output",
		zap.String("command", "systemctl is-active consul"),
		zap.String("output", statusOutput),
		zap.Error(err))

	if err != nil {
		// Check if it's just not active yet
		status := strings.TrimSpace(statusOutput)
		if status == "activating" {
			log.Info("Consul service is still activating", zap.String("status", status))
			return nil
		}
		log.Error("Failed to verify service is active",
			zap.Error(err),
			zap.String("status_output", statusOutput))
		return fmt.Errorf("failed to verify service is active: %w", err)
	}

	status := strings.TrimSpace(statusOutput)
	if status != "active" {
		// Accept "activating" as a valid state - service is starting up
		if status == "activating" {
			log.Info("Consul service is activating - this is normal during startup",
				zap.String("status", status))
			return nil
		}
		return fmt.Errorf("consul service is not active: %s", status)
	}

	log.Info("Consul service started and enabled successfully",
		zap.String("status", strings.TrimSpace(statusOutput)))

	return nil
}
