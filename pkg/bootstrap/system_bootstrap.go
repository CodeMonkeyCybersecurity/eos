// pkg/bootstrap/system_bootstrap.go
//
// This file provides lightweight bootstrap detection and prompting functionality.
// It integrates with the eos_cli.Wrap function to automatically detect when
// a system hasn't been bootstrapped and prompt the user to bootstrap before
// running commands that require a bootstrapped system.
//
// Usage:
//   - IsSystemBootstrapped() checks for bootstrap markers with minimal performance impact
//   - ShouldPromptForBootstrap() determines if a command should trigger bootstrap prompting
//   - PromptForBootstrap() handles user interaction for bootstrap decision
//   - MarkSystemAsBootstrapped() creates bootstrap markers after successful bootstrap
//
// The system checks for several bootstrap indicators:
//   - /opt/eos/.bootstrapped (primary marker)
//   - /opt/vault/init.json (vault initialization marker)
//   - /etc/eos/bootstrap.conf
//   - /var/lib/eos/bootstrapped
//   - ~/.eos/bootstrapped

package bootstrap

import (
	"os"
	"path/filepath"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

var (
	// Bootstrap marker files - these indicate a bootstrapped system
	bootstrapMarkerFile = "/opt/eos/.bootstrapped"
	vaultMarkerFile     = "/opt/vault/init.json"
)

// IsSystemBootstrapped performs a lightweight check to determine if the system has been bootstrapped.
// This is designed to be fast with minimal performance impact.
func IsSystemBootstrapped() bool {
	// Check primary bootstrap marker
	if _, err := os.Stat(bootstrapMarkerFile); err == nil {
		return true
	}

	// Check for vault initialization as a secondary indicator
	if _, err := os.Stat(vaultMarkerFile); err == nil {
		return true
	}

	// Check for other common bootstrap indicators
	bootstrapIndicators := []string{
		"/etc/eos/bootstrap.conf",
		"/var/lib/eos/bootstrapped",
		filepath.Join(os.Getenv("HOME"), ".eos/bootstrapped"),
	}

	for _, indicator := range bootstrapIndicators {
		if _, err := os.Stat(indicator); err == nil {
			return true
		}
	}

	return false
}

// ShouldPromptForBootstrap determines if we should prompt the user to bootstrap.
// Returns true if the system is not bootstrapped and the command requires it.
func ShouldPromptForBootstrap(cmdName string) bool {
	// Commands that don't require bootstrap
	exemptCommands := map[string]bool{
		"help":       true,
		"version":    true,
		"bootstrap":  true,
		"self":       true,
		"update":     true,     // Self-update shouldn't require bootstrap
		"install":    true,
		"completion": true,
		"test":       true,     // Don't prompt during testing
		"test-cmd":   true,     // Test command from wrap tests
		"panic-cmd":  true,     // Test command from wrap tests
		"long-running": true,   // Test command from wrap tests
	}

	// Check if command is exempt
	if exemptCommands[cmdName] {
		return false
	}

	// Check if already bootstrapped
	if IsSystemBootstrapped() {
		return false
	}

	// For all other commands, we should prompt
	return true
}

// PromptForBootstrap prompts the user to bootstrap the system.
// Returns true if the user wants to bootstrap, false otherwise.
func PromptForBootstrap(rc *eos_io.RuntimeContext) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("System has not been bootstrapped")
	logger.Info("terminal prompt: ⚠️  This system has not been bootstrapped.")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Bootstrap will install and configure:")
	logger.Info("terminal prompt:   • Salt (configuration management)")
	logger.Info("terminal prompt:   • Vault, Consul, Nomad (orchestration)")
	logger.Info("terminal prompt:   • OSQuery, Trivy (security monitoring)")
	logger.Info("terminal prompt:   • Ubuntu hardening (optional)")
	logger.Info("terminal prompt: ")

	response, err := eos_io.PromptInput(rc, "Would you like to bootstrap now? (y/N): ", "bootstrap_choice")
	if err != nil {
		return false, err
	}

	// Check if user wants to bootstrap
	if response == "y" || response == "Y" || response == "yes" || response == "Yes" {
		logger.Info("User chose to bootstrap", zap.String("response", response))
		return true, nil
	}

	logger.Info("User declined bootstrap", zap.String("response", response))
	return false, nil
}

// MarkSystemAsBootstrapped creates the bootstrap marker file.
// This should be called after successful bootstrap completion.
func MarkSystemAsBootstrapped(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create directory if it doesn't exist
	dir := filepath.Dir(bootstrapMarkerFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		logger.Error("Failed to create bootstrap marker directory",
			zap.String("directory", dir),
			zap.Error(err))
		return err
	}

	// Create marker file
	if err := os.WriteFile(bootstrapMarkerFile, []byte("bootstrapped\n"), 0644); err != nil {
		logger.Error("Failed to create bootstrap marker file",
			zap.String("file", bootstrapMarkerFile),
			zap.Error(err))
		return err
	}

	logger.Info("System marked as bootstrapped",
		zap.String("marker_file", bootstrapMarkerFile))
	return nil
}