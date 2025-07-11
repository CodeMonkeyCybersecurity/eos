package cleanup

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VerifyCleanup verifies that Vault cleanup was successful
// Migrated from cmd/delete/secrets.go verifyCleanup
func VerifyCleanup(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Prepare verification checks
	logger.Info("Assessing cleanup verification requirements")
	
	// INTERVENE - Perform verification checks
	logger.Info("Verifying cleanup completion")
	
	// Check for remaining processes
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ps",
		Args:    []string{"aux"},
	})
	if err == nil && strings.Contains(output, "vault") {
		logger.Warn("Vault processes may still be running",
			zap.String("ps_output", output))
	}
	
	// Check for remaining systemd services
	services := []string{"vault.service", "vault-agent-eos.service"}
	for _, service := range services {
		if err := execute.RunSimple(rc.Ctx, "systemctl", "is-active", service); err == nil {
			logger.Warn("Service still active", zap.String("service", service))
		}
	}
	
	// Check for critical files that should be gone
	criticalPaths := []string{
		"/etc/vault.d/vault.hcl",
		"/etc/vault-agent-eos.hcl",
		"/etc/systemd/system/vault.service",
		"/etc/systemd/system/vault-agent-eos.service",
		"/run/eos/vault_agent_eos.token",
	}
	
	foundPaths := []string{}
	for _, path := range criticalPaths {
		if _, err := os.Stat(path); err == nil {
			foundPaths = append(foundPaths, path)
		}
	}
	
	// Reload systemd daemon to ensure service definitions are refreshed
	if err := execute.RunSimple(rc.Ctx, "systemctl", "daemon-reload"); err != nil {
		logger.Warn("Failed to reload systemd daemon", zap.Error(err))
	}
	
	// EVALUATE - Check results
	if len(foundPaths) > 0 {
		logger.Warn("Some critical files still exist",
			zap.Strings("remaining_files", foundPaths))
		return fmt.Errorf("cleanup incomplete - %d critical files remain", len(foundPaths))
	}
	
	logger.Info("Cleanup verification passed")
	return nil
}