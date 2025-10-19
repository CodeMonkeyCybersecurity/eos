// pkg/consul/acl/token.go
// ACL token management for Consul operations

package acl

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TokenConfig holds ACL token configuration
type TokenConfig struct {
	Token      string
	TokenFile  string
	AutoDetect bool
}

// DetectACLMode checks if Consul has ACLs enabled
func DetectACLMode(ctx context.Context) (bool, error) {
	logger := otelzap.Ctx(ctx)

	// Try to run a command that requires ACL permissions
	output, err := execute.Run(ctx, execute.Options{
		Command: "consul",
		Args:    []string{"acl", "bootstrap", "-dry-run"},
		Capture: true,
	})

	// If ACLs are enabled, this will error with "ACL bootstrap no longer allowed"
	// If ACLs are disabled, it will error with "ACL support disabled"
	if err != nil {
		if strings.Contains(output, "ACL support disabled") {
			logger.Debug("ACL mode: disabled")
			return false, nil
		}
		// Enabled but might already be bootstrapped
		logger.Debug("ACL mode: enabled")
		return true, nil
	}

	logger.Debug("ACL mode: enabled (not yet bootstrapped)")
	return true, nil
}

// GetToken retrieves ACL token from environment or file
func GetToken(ctx context.Context, config *TokenConfig) (string, error) {
	logger := otelzap.Ctx(ctx)

	// 1. Check if token provided directly
	if config.Token != "" {
		logger.Debug("Using ACL token from configuration")
		return config.Token, nil
	}

	// 2. Check CONSUL_HTTP_TOKEN environment variable
	if token := os.Getenv("CONSUL_HTTP_TOKEN"); token != "" {
		logger.Debug("Using ACL token from CONSUL_HTTP_TOKEN")
		return token, nil
	}

	// 3. Check token file if specified
	if config.TokenFile != "" {
		data, err := os.ReadFile(config.TokenFile)
		if err != nil {
			return "", fmt.Errorf("failed to read ACL token file %s: %w", config.TokenFile, err)
		}
		token := strings.TrimSpace(string(data))
		logger.Debug("Using ACL token from file", zap.String("file", config.TokenFile))
		return token, nil
	}

	// 4. Check default token file locations
	defaultPaths := []string{
		"/etc/consul.d/acl-token",
		"/var/lib/consul/acl-token",
		os.ExpandEnv("$HOME/.consul-token"),
	}

	for _, path := range defaultPaths {
		if data, err := os.ReadFile(path); err == nil {
			token := strings.TrimSpace(string(data))
			if token != "" {
				logger.Debug("Using ACL token from default location", zap.String("file", path))
				return token, nil
			}
		}
	}

	return "", fmt.Errorf("ACL token not found\n" +
		"Consul has ACLs enabled but no token was provided.\n\n" +
		"Provide token via:\n" +
		"  1. Environment: export CONSUL_HTTP_TOKEN=<token>\n" +
		"  2. File: Save token to /etc/consul.d/acl-token\n" +
		"  3. Flag: --acl-token=<token>\n\n" +
		"Get token: consul acl token list")
}

// SetupEnvironment sets up environment variables for Consul commands
func SetupEnvironment(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}

	// Set CONSUL_HTTP_TOKEN for child processes
	if err := os.Setenv("CONSUL_HTTP_TOKEN", token); err != nil {
		return fmt.Errorf("failed to set CONSUL_HTTP_TOKEN: %w", err)
	}

	logger := otelzap.Ctx(ctx)
	logger.Debug("ACL token configured for Consul commands")

	return nil
}
