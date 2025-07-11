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
	}
	output, err := execute.Run(rc.Ctx, checkCmd)
	if err != nil {
		return fmt.Errorf("failed to check service existence: %w", err)
	}
	
	if !strings.Contains(output, "consul.service") {
		return fmt.Errorf("consul.service not found in systemd")
	}
	
	// INTERVENE - Enable and start service
	log.Info("Starting Consul service")
	
	steps := []execute.Options{
		{Command: "systemctl", Args: []string{"enable", "consul"}},
		{Command: "systemctl", Args: []string{"start", "consul"}},
	}
	
	for _, step := range steps {
		if err := execute.RunSimple(rc.Ctx, step.Command, step.Args...); err != nil {
			cmdStr := strings.Join(append([]string{step.Command}, step.Args...), " ")
			return fmt.Errorf("%s failed: %w", cmdStr, err)
		}
		log.Debug("Executed systemctl command",
			zap.String("command", step.Command),
			zap.Strings("args", step.Args))
	}
	
	// EVALUATE - Verify service is running
	log.Info("Evaluating Consul service status")
	
	statusCmd := execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "consul"},
	}
	statusOutput, err := execute.Run(rc.Ctx, statusCmd)
	if err != nil {
		// Check if it's just not active yet
		if strings.TrimSpace(statusOutput) == "activating" {
			log.Info("Consul service is still activating")
			return nil
		}
		return fmt.Errorf("failed to verify service is active: %w", err)
	}
	
	if strings.TrimSpace(statusOutput) != "active" {
		return fmt.Errorf("consul service is not active: %s", statusOutput)
	}
	
	log.Info("Consul service started and enabled successfully",
		zap.String("status", strings.TrimSpace(statusOutput)))
	
	return nil
}