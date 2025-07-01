// pkg/application/vault/commands.go
package vault

import (
	"context"
	"fmt"

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
