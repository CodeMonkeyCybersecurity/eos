// pkg/consul/acl/token.go
// ACL token management for Consul operations

package acl

import (
	"context"
	"fmt"
	"os"
	"strings"

	consulapi "github.com/hashicorp/consul/api"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TokenConfig holds ACL token configuration
type TokenConfig struct {
	Token      string
	TokenFile  string
	AutoDetect bool
}

// DetectACLMode checks if Consul has ACLs enabled using the official Consul SDK
//
// This function uses the Consul SDK to make an unauthenticated API call to determine
// ACL status without relying on CLI command parsing.
//
// The function attempts to list ACL policies, which is a read-only operation that will:
//   - Return HTTP 401 "ACL support disabled" if ACLs are disabled
//   - Return HTTP 403 "Permission denied" if ACLs are enabled but we lack a token
//   - Return HTTP 200 with data if ACLs are enabled and we have a valid token
//
// Returns:
//   - true if ACLs are enabled
//   - false if ACLs are disabled
//   - error if detection fails (network issues, Consul down, etc.)
//
// Implementation Note:
//   - Migrated from CLI command (`consul acl bootstrap --dry-run`) to SDK in v2.0
//   - Fail-safe: assumes ACLs are disabled if detection is uncertain
//   - This allows auto-enablement prompt rather than silently skipping
func DetectACLMode(ctx context.Context) (bool, error) {
	logger := otelzap.Ctx(ctx)

	// ASSESS - Create Consul client (no token needed for detection)
	config := consulapi.DefaultConfig()
	config.Address = shared.GetConsulHostPort() // Usually localhost:8500

	client, err := consulapi.NewClient(config)
	if err != nil {
		return false, fmt.Errorf("failed to create Consul client for ACL detection: %w", err)
	}

	// ASSESS - Attempt to list ACL policies (read-only operation)
	// This will reveal ACL status through the HTTP status code
	_, _, err = client.ACL().PolicyList(nil)

	if err != nil {
		// Check error message for specific ACL states
		errMsg := err.Error()

		// HTTP 401: ACLs are explicitly disabled
		if strings.Contains(errMsg, "ACL support disabled") {
			logger.Debug("ACL mode: disabled (PolicyList returned 'ACL support disabled')")
			return false, nil
		}

		// HTTP 403: ACLs are enabled, but we don't have a valid token
		// This is expected when checking ACL status without authentication
		if strings.Contains(errMsg, "Permission denied") ||
			strings.Contains(errMsg, "403") {
			logger.Debug("ACL mode: enabled (PolicyList returned permission denied)")
			return true, nil
		}

		// Unexpected error (network failure, Consul down, etc.)
		// FAIL-SAFE: Assume ACLs are disabled so we offer to enable them
		// Better to prompt unnecessarily than skip enablement
		logger.Warn("Could not detect ACL mode definitively",
			zap.Error(err),
			zap.String("error_message", errMsg),
			zap.String("note", "Assuming ACLs disabled (fail-safe default)"))

		return false, nil
	}

	// Success: ACLs are enabled AND we have a valid token
	logger.Debug("ACL mode: enabled (PolicyList succeeded with valid token)")
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
