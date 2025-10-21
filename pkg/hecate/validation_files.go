// pkg/hecate/validation_files.go

package hecate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ValidateGeneratedFiles validates docker-compose.yml, .env, and Caddyfile after generation
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Check if required files exist
// - Intervene: Run validation tools (docker compose config, caddy validate) via verify package
// - Evaluate: Return errors with remediation if validation fails
func ValidateGeneratedFiles(rc *eos_io.RuntimeContext, hecatePath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Validating generated Hecate files",
		zap.String("path", hecatePath))

	// ASSESS: Check required files exist
	requiredFiles := map[string]string{
		"docker-compose.yml": "Docker Compose service definitions",
		".env":               "Environment variables",
		"Caddyfile":          "Caddy reverse proxy configuration",
	}

	for filename, description := range requiredFiles {
		filePath := filepath.Join(hecatePath, filename)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return fmt.Errorf("required file missing: %s (%s)", filename, description)
		}
		logger.Debug("File exists",
			zap.String("file", filename))
	}

	// INTERVENE & EVALUATE: Validate all files using verify package
	if err := verify.ValidateGeneratedFiles(rc.Ctx, hecatePath); err != nil {
		return fmt.Errorf("file validation failed: %w", err)
	}

	// All validations passed
	logger.Info("File validation completed successfully")
	return nil
}

// validateDockerCompose validates docker-compose.yml using 'docker compose config'
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Check if docker command is available
// - Intervene: Run 'docker compose config' to parse and validate
// - Evaluate: Return detailed errors if validation fails
func validateDockerCompose(rc *eos_io.RuntimeContext, hecatePath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Validating docker-compose.yml")

	// ASSESS: Check if docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		logger.Warn("Docker not found, skipping validation",
			zap.Error(err))
		return nil // Don't fail if docker isn't available
	}

	composeFile := filepath.Join(hecatePath, "docker-compose.yml")
	envFile := filepath.Join(hecatePath, ".env")

	// INTERVENE: Run docker compose config to validate
	ctx, cancel := context.WithTimeout(rc.Ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "--env-file", envFile, "config")
	output, err := cmd.CombinedOutput()

	if err != nil {
		// EVALUATE: Validation failed - parse error for details
		outputStr := string(output)

		// Extract useful error information
		var errorLines []string
		for _, line := range strings.Split(outputStr, "\n") {
			// Collect WARN and error lines
			if strings.Contains(line, "WARN") || strings.Contains(line, "invalid") || strings.Contains(line, "Error") {
				errorLines = append(errorLines, line)
			}
		}

		logger.Error("Docker Compose validation failed",
			zap.String("compose_file", composeFile),
			zap.String("env_file", envFile),
			zap.Strings("errors", errorLines))

		// Check for specific error patterns
		if strings.Contains(outputStr, "variable is not set") {
			return fmt.Errorf("docker-compose.yml contains undefined variables:\n%s\n\n"+
				"This indicates a bug in .env file generation.\n"+
				"Missing or improperly escaped variables in .env file.\n"+
				"Full output:\n%s",
				strings.Join(errorLines, "\n"),
				outputStr)
		}

		if strings.Contains(outputStr, "invalid IP address") {
			return fmt.Errorf("docker-compose.yml contains invalid port mapping:\n%s\n\n"+
				"This indicates a bug in port variable substitution.\n"+
				"Check COMPOSE_PORT_HTTP and COMPOSE_PORT_HTTPS in .env file.\n"+
				"Full output:\n%s",
				strings.Join(errorLines, "\n"),
				outputStr)
		}

		// Generic validation failure
		return fmt.Errorf("docker-compose.yml validation failed:\n%s\n\n"+
			"Run manually to debug:\n"+
			"  docker compose -f %s --env-file %s config\n\n"+
			"Full output:\n%s",
			strings.Join(errorLines, "\n"),
			composeFile,
			envFile,
			outputStr)
	}

	// EVALUATE: Validation succeeded
	logger.Info("docker-compose.yml validation passed",
		zap.String("file", composeFile))

	return nil
}

// validateCaddyfile validates Caddyfile using 'caddy validate'
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Check if caddy command is available
// - Intervene: Run 'caddy validate' to check syntax
// - Evaluate: Return errors if validation fails
func validateCaddyfile(rc *eos_io.RuntimeContext, hecatePath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Validating Caddyfile")

	// ASSESS: Check if caddy is available
	caddyPath, err := exec.LookPath("caddy")
	if err != nil {
		// Caddy binary not available - this is expected if using Docker
		logger.Debug("Caddy binary not found, skipping Caddyfile validation")
		return nil
	}

	caddyfile := filepath.Join(hecatePath, "Caddyfile")

	// INTERVENE: Run caddy validate
	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, caddyPath, "validate", "--config", caddyfile)
	output, err := cmd.CombinedOutput()

	if err != nil {
		// EVALUATE: Validation failed
		logger.Error("Caddyfile validation failed",
			zap.String("caddyfile", caddyfile),
			zap.String("output", string(output)))

		return fmt.Errorf("Caddyfile syntax error:\n%s\n\n"+
			"Run manually to debug:\n"+
			"  caddy validate --config %s",
			string(output),
			caddyfile)
	}

	// EVALUATE: Validation succeeded
	logger.Info("Caddyfile validation passed",
		zap.String("file", caddyfile))

	return nil
}
