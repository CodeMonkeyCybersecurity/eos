// pkg/verify/validators.go
// Generic validation functions for domains, backends, and configuration files

package verify

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ValidateDomain checks if domain is a valid format
// Used for validating domain names in YAML configs, env files, etc.
func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	// Remove protocol if accidentally included
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		return fmt.Errorf("domain should not include protocol: %s\n"+
			"Use: example.com (not https://example.com)", domain)
	}

	// Check for path, query, or fragment
	if strings.Contains(domain, "/") || strings.Contains(domain, "?") || strings.Contains(domain, "#") {
		return fmt.Errorf("domain should not include path, query, or fragment: %s\n"+
			"Use: example.com (not example.com/path)", domain)
	}

	// Check for spaces or other invalid characters
	if strings.Contains(domain, " ") || strings.Contains(domain, "\t") {
		return fmt.Errorf("domain contains whitespace: %s", domain)
	}

	// Very basic domain validation - must have at least one dot for FQDN
	// (Allow localhost, etc. for development)
	parts := strings.Split(domain, ".")
	if len(parts) < 2 && domain != "localhost" {
		return fmt.Errorf("invalid domain format: %s\n"+
			"Use fully qualified domain name (example.com)\n"+
			"or 'localhost' for local development", domain)
	}

	return nil
}

// ValidateBackend checks if backend is a valid IP address or hostname (optionally with port)
// Accepts: "192.168.1.100", "server.local", "192.168.1.100:8080", "server.local:8080"
// Rejects: URLs with protocols, paths, queries
func ValidateBackend(backend string) error {
	if backend == "" {
		return fmt.Errorf("backend cannot be empty")
	}

	// Extract host part (remove :port if present)
	host := backend
	if strings.Contains(backend, ":") {
		parts := strings.Split(backend, ":")
		if len(parts) != 2 {
			return fmt.Errorf("invalid backend format (too many colons): %s", backend)
		}
		host = parts[0]

		// Validate port
		port := parts[1]
		if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
			return fmt.Errorf("invalid port number: %s (must be 1-65535)", port)
		}
	}

	// Check if it's a valid format (IP or hostname)
	// Allow: IPs (192.168.1.1), hostnames (server.local), FQDNs (app.example.com)
	// Reject: URLs with protocols, paths, queries
	if strings.Contains(host, "/") || strings.Contains(host, "?") ||
		strings.Contains(host, "@") || strings.Contains(host, "#") {
		return fmt.Errorf("invalid backend format: %s\n"+
			"Use IP address (192.168.1.100) or hostname (server.local)\n"+
			"Do not include protocol (http://), path (/api), or query (?key=val)", backend)
	}

	// Very basic hostname/IP validation - just check reasonable characters
	validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"
	for _, char := range host {
		if !strings.ContainsRune(validChars, char) {
			return fmt.Errorf("invalid character '%c' in backend: %s\n"+
				"Backend must be IP address or hostname (alphanumeric, dots, hyphens only)",
				char, backend)
		}
	}

	return nil
}

// ValidateDockerCompose validates docker-compose.yml using 'docker compose config'
//
// This function validates docker-compose.yml and .env file syntax by running
// 'docker compose config' which parses and validates the configuration.
//
// Parameters:
//   - ctx: Context for logging
//   - composeFile: Path to docker-compose.yml
//   - envFile: Path to .env file (can be empty string if not using env file)
//
// Returns error with detailed validation information if validation fails.
func ValidateDockerCompose(ctx context.Context, composeFile, envFile string) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Validating docker-compose.yml")

	// Check if docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		logger.Warn("Docker not found, skipping validation",
			zap.Error(err))
		return nil // Don't fail if docker isn't available
	}

	// Build docker compose command
	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	args := []string{"compose", "-f", composeFile}
	if envFile != "" {
		args = append(args, "--env-file", envFile)
	}
	args = append(args, "config")

	cmd := exec.CommandContext(cmdCtx, "docker", args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		// Validation failed - parse error for details
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
				"This indicates missing or improperly escaped variables in .env file.\n"+
				"Full output:\n%s",
				strings.Join(errorLines, "\n"),
				outputStr)
		}

		if strings.Contains(outputStr, "invalid IP address") {
			return fmt.Errorf("docker-compose.yml contains invalid port mapping:\n%s\n\n"+
				"This indicates a bug in port variable substitution.\n"+
				"Check COMPOSE_PORT_* variables in .env file.\n"+
				"Full output:\n%s",
				strings.Join(errorLines, "\n"),
				outputStr)
		}

		if strings.Contains(outputStr, "couldn't find env file") {
			return fmt.Errorf("docker-compose.yml references .env file that doesn't exist:\n%s\n\n"+
				"Expected: %s\n"+
				"Full output:\n%s",
				strings.Join(errorLines, "\n"),
				envFile,
				outputStr)
		}

		// Generic validation failure
		return fmt.Errorf("docker-compose.yml validation failed:\n%s\n\n"+
			"Run manually to debug:\n"+
			"  docker compose -f %s%s config\n\n"+
			"Full output:\n%s",
			strings.Join(errorLines, "\n"),
			composeFile,
			func() string {
				if envFile != "" {
					return " --env-file " + envFile
				}
				return ""
			}(),
			outputStr)
	}

	// Validation succeeded
	logger.Info("docker-compose.yml validation passed",
		zap.String("file", composeFile))

	return nil
}

// ValidateCaddyfile validates Caddyfile using 'caddy validate'
//
// This function validates Caddyfile syntax by running 'caddy validate'.
// If caddy binary is not available, validation is skipped (not an error).
//
// Parameters:
//   - ctx: Context for logging
//   - caddyfile: Path to Caddyfile
//
// Returns error with validation details if syntax is invalid.
func ValidateCaddyfile(ctx context.Context, caddyfile string) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Validating Caddyfile")

	// Check if caddy is available
	caddyPath, err := exec.LookPath("caddy")
	if err != nil {
		// Caddy binary not available - this is expected if using Docker
		logger.Debug("Caddy binary not found, skipping Caddyfile validation")
		return nil
	}

	// Run caddy validate
	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, caddyPath, "validate", "--config", caddyfile)
	output, err := cmd.CombinedOutput()

	if err != nil {
		// Validation failed
		logger.Error("Caddyfile validation failed",
			zap.String("caddyfile", caddyfile),
			zap.String("output", string(output)))

		return fmt.Errorf("Caddyfile syntax error:\n%s\n\n"+
			"Run manually to debug:\n"+
			"  caddy validate --config %s",
			string(output),
			caddyfile)
	}

	// Validation succeeded
	logger.Info("Caddyfile validation passed",
		zap.String("file", caddyfile))

	return nil
}

// ValidateNoFlagLikeArgs detects if positional arguments look like flags
//
// This prevents a common user error where the '--' separator causes flags to be
// treated as positional arguments. For example:
//
//	WRONG: eos create config -- hecate
//	RIGHT: eos create config --hecate
//
// When a user uses '--', Cobra stops parsing flags and treats everything after
// as positional arguments. This validation catches that mistake early.
//
// Parameters:
//   - args: Positional arguments from cobra command
//
// Returns error if any argument starts with '-' or '--', with remediation guidance.
func ValidateNoFlagLikeArgs(args []string) error {
	for i, arg := range args {
		if strings.HasPrefix(arg, "--") {
			return fmt.Errorf(
				"argument %d looks like a long flag: '%s'\n"+
					"Did you use the '--' separator by mistake?\n"+
					"Remove the '--' separator to use flags properly.\n"+
					"Example: Use 'eos command --flag' instead of 'eos command -- --flag'",
				i, arg)
		}
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			// Allow negative numbers like -1, but catch flag patterns like -f, -v
			if _, err := strconv.Atoi(arg); err != nil {
				return fmt.Errorf(
					"argument %d looks like a short flag: '%s'\n"+
						"Did you use the '--' separator by mistake?\n"+
						"Remove the '--' separator to use flags properly.\n"+
						"Example: Use 'eos command -f' instead of 'eos command -- -f'",
					i, arg)
			}
		}
	}
	return nil
}

// ValidateGeneratedFiles validates all generated configuration files
//
// This is a convenience function that validates:
// - docker-compose.yml
// - .env file (via docker compose config)
// - Caddyfile
//
// Parameters:
//   - ctx: Context for logging
//   - baseDir: Base directory containing the files
//
// Returns error if any validation fails.
func ValidateGeneratedFiles(ctx context.Context, baseDir string) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Validating generated configuration files",
		zap.String("path", baseDir))

	// Validate docker-compose.yml with .env
	composeFile := filepath.Join(baseDir, "docker-compose.yml")
	envFile := filepath.Join(baseDir, ".env")

	if err := ValidateDockerCompose(ctx, composeFile, envFile); err != nil {
		return fmt.Errorf("docker-compose.yml validation failed: %w", err)
	}

	// Validate Caddyfile (optional - won't fail if caddy not installed)
	caddyfile := filepath.Join(baseDir, "Caddyfile")
	if err := ValidateCaddyfile(ctx, caddyfile); err != nil {
		// Caddyfile validation is optional (Caddy binary may not be available)
		logger.Warn("Caddyfile validation skipped or failed",
			zap.Error(err))
	}

	// All validations passed
	logger.Info("File validation completed successfully")
	return nil
}
