// pkg/application/vault/commands.go
package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
)

// Commands provides application-level vault operations
type Commands struct {
	service vault.VaultService
}

// NewCommands creates a new vault command handler
func NewCommands(service vault.VaultService) *Commands {
	return &Commands{service: service}
}

// GetSecretCommand represents a command to get a secret
type GetSecretCommand struct {
	Path string
}

// Execute retrieves a secret from vault
func (c *Commands) Execute(ctx context.Context, cmd GetSecretCommand) (*vault.Secret, error) {
	// Application-level validation
	if cmd.Path == "" {
		return nil, fmt.Errorf("secret path is required")
	}

	// Validate secret path
	if err := validateSecretPath(cmd.Path); err != nil {
		return nil, fmt.Errorf("invalid secret path: %w", err)
	}

	// Check health first
	if err := c.service.CheckHealth(ctx); err != nil {
		return nil, fmt.Errorf("vault health check failed: %w", err)
	}

	// Get the secret
	secret, err := c.service.GetSecret(ctx, cmd.Path)
	if err != nil {
		return nil, fmt.Errorf("getting secret: %w", err)
	}

	return secret, nil
}

// validateSecretPath validates that a Vault secret path is safe
func validateSecretPath(path string) error {
	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("path cannot contain '..' (path traversal)")
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("path cannot contain null bytes")
	}

	// Check for control characters
	if strings.ContainsAny(path, "\n\r\t") {
		return fmt.Errorf("path cannot contain control characters")
	}

	// Check for command injection patterns
	if strings.ContainsAny(path, ";|&`$(){}[]<>") {
		return fmt.Errorf("path contains invalid characters")
	}

	// Check for protocol handlers (attempting to access files or URLs)
	if strings.Contains(path, "://") || strings.HasPrefix(path, "file:") {
		return fmt.Errorf("path cannot contain protocol handlers")
	}

	// Check path length limit
	if len(path) > 1024 {
		return fmt.Errorf("path too long (max 1024 characters)")
	}

	// Vault paths should not start with /
	if strings.HasPrefix(path, "/") {
		return fmt.Errorf("vault paths should not start with /")
	}

	return nil
}
