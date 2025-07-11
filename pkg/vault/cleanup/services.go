package cleanup

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// StopVaultServices stops and disables all Vault-related services
// Migrated from cmd/delete/secrets.go stopVaultServices
func StopVaultServices(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Identify services to stop
	logger.Info("Assessing Vault services to stop")
	
	services := []string{
		"vault-agent-eos.service",
		"vault.service",
		"vault-backup.timer",
		"vault-backup.service",
	}
	
	// INTERVENE - Stop and disable services
	logger.Info("Stopping and disabling Vault services")
	
	for _, service := range services {
		// Stop service
		logger.Info("Stopping service", zap.String("service", service))
		if err := execute.RunSimple(rc.Ctx, "systemctl", "stop", service); err != nil {
			logger.Warn("Failed to stop service (may not exist)",
				zap.String("service", service),
				zap.Error(err))
		}
		
		// Disable service
		logger.Info("Disabling service", zap.String("service", service))
		if err := execute.RunSimple(rc.Ctx, "systemctl", "disable", service); err != nil {
			logger.Warn("Failed to disable service (may not exist)",
				zap.String("service", service),
				zap.Error(err))
		}
	}
	
	// Kill any remaining Vault processes
	logger.Info("Killing any remaining Vault processes")
	if err := execute.RunSimple(rc.Ctx, "pkill", "-f", "vault server"); err != nil {
		logger.Info("No vault server processes found")
	}
	if err := execute.RunSimple(rc.Ctx, "pkill", "-f", "vault agent"); err != nil {
		logger.Info("No vault agent processes found")
	}
	
	// Wait a moment for processes to terminate
	time.Sleep(2 * time.Second)
	
	// EVALUATE - Check if all services stopped
	logger.Info("Vault services stop completed")
	
	return nil
}