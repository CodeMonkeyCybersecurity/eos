package service

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Start enables and starts the Consul service
// Migrated from cmd/create/consul.go startConsulService
func Start(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check service state
	log.Info("Assessing Consul service state")

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
		{Command: "systemctl", Args: []string{"start", "consul"}},
	}

	for _, step := range steps {
		cmdStr := strings.Join(append([]string{step.Command}, step.Args...), " ")
		log.Info("Executing systemctl command", zap.String("command", cmdStr))
		
		if err := execute.RunSimple(rc.Ctx, step.Command, step.Args...); err != nil {
			log.Error("systemctl command failed", 
				zap.String("command", cmdStr),
				zap.Error(err))
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
		if strings.TrimSpace(statusOutput) == "activating" {
			log.Info("Consul service is still activating", zap.String("status", statusOutput))
			return nil
		}
		log.Error("Failed to verify service is active", 
			zap.Error(err),
			zap.String("status_output", statusOutput))
		return fmt.Errorf("failed to verify service is active: %w", err)
	}

	if strings.TrimSpace(statusOutput) != "active" {
		return fmt.Errorf("consul service is not active: %s", statusOutput)
	}

	log.Info("Consul service started and enabled successfully",
		zap.String("status", strings.TrimSpace(statusOutput)))

	return nil
}
