// pkg/hecate/validation_caddy_live.go
// Docker exec-based Caddy validation and reload (Phase 2)
// This provides validation and reload without requiring Admin API port exposure

package hecate

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ValidateCaddyfileLive validates Caddyfile by running caddy validate inside the container
// This method does NOT require Admin API port exposure (works in any Docker network mode)
//
// ASSESS → INTERVENE → EVALUATE pattern:
// - ASSESS: Check container is running
// - INTERVENE: Execute caddy validate inside container
// - EVALUATE: Check exit code and parse output
func ValidateCaddyfileLive(rc *eos_io.RuntimeContext, caddyfilePath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Validating Caddyfile via docker exec",
		zap.String("container", CaddyContainerName),
		zap.String("caddyfile", caddyfilePath))

	// ASSESS: Check container is running
	// Note: Container name verification happens in container.ExecCommandInContainer

	// INTERVENE: Execute caddy validate inside container
	cfg := container.ExecConfig{
		ContainerName: CaddyContainerName,
		Cmd:           []string{"caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"},
		Tty:           false,
	}

	output, err := container.ExecCommandInContainer(rc, cfg)

	// EVALUATE: Check results
	if err != nil {
		logger.Error("Caddy validation failed",
			zap.String("output", output),
			zap.Error(err))

		// Parse output for user-friendly error message
		errorSummary := parseValidationError(output)

		return fmt.Errorf("Caddyfile validation failed:\n%s\n\n"+
			"Fix syntax errors and try again.\n"+
			"Caddyfile location: %s\n\n"+
			"Full validation output:\n%s",
			errorSummary, caddyfilePath, output)
	}

	logger.Info("Caddy validation passed",
		zap.String("output", strings.TrimSpace(output)))

	return nil
}

// ReloadCaddyViaExec reloads Caddy configuration by executing caddy reload inside the container
// This performs a zero-downtime reload without requiring Admin API port exposure
func ReloadCaddyViaExec(rc *eos_io.RuntimeContext, caddyfilePath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Reloading Caddy via docker exec",
		zap.String("container", CaddyContainerName),
		zap.String("caddyfile", caddyfilePath))

	// ASSESS: Validate first to ensure config is valid
	if err := ValidateCaddyfileLive(rc, caddyfilePath); err != nil {
		return fmt.Errorf("validation failed, not reloading: %w", err)
	}

	// INTERVENE: Execute caddy reload inside container
	cfg := container.ExecConfig{
		ContainerName: CaddyContainerName,
		Cmd:           []string{"caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"},
		Tty:           false,
	}

	output, err := container.ExecCommandInContainer(rc, cfg)

	// EVALUATE: Check results
	if err != nil {
		logger.Error("Caddy reload failed",
			zap.String("output", output),
			zap.Error(err))

		return fmt.Errorf("Caddy reload failed: %s\n\n"+
			"Check Caddy logs: docker logs %s\n\n"+
			"Full output:\n%s",
			err, CaddyContainerName, output)
	}

	logger.Info("Caddy reloaded successfully",
		zap.String("output", strings.TrimSpace(output)))

	return nil
}

// parseValidationError extracts the most relevant error message from caddy validate output
// Caddy validation errors can be verbose - this extracts the key issue
func parseValidationError(output string) string {
	// Caddy validation errors typically contain "Error:" followed by the issue
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(trimmed), "error") {
			return trimmed
		}
	}

	// Fallback: return first non-empty line
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			return trimmed
		}
	}

	// Last resort: return full output (truncated)
	if len(output) > 200 {
		return output[:200] + "..."
	}
	return output
}
