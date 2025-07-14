// pkg/infrastructure/vault/client.go
package vault

import (
	"context"
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// Client implements the VaultService interface using HashiCorp Vault
type Client struct {
	client *vaultapi.Client
	logger *zap.Logger
}

// NewClient creates a new vault infrastructure client
func NewClient(addr string, logger *zap.Logger) (*Client, error) {
	config := vaultapi.DefaultConfig()
	config.Address = addr

	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	return &Client{
		client: client,
		logger: logger,
	}, nil
}

// CheckHealth implements VaultService.CheckHealth
func (c *Client) CheckHealth(ctx context.Context) error {
	health, err := c.client.Sys().Health()
	if err != nil {
		return fmt.Errorf("checking health: %w", err)
	}

	if health.Sealed {
		return ErrVaultSealed
	}

	return nil
}

// APIClient returns the underlying HashiCorp Vault API client
// This is needed for functions that expect *api.Client directly
func (c *Client) APIClient() *vaultapi.Client {
	return c.client
}

// Address returns the Vault server address
func (c *Client) Address() string {
	return c.client.Address()
}

// GetSecret implements VaultService.GetSecret
func (c *Client) GetSecret(ctx context.Context, path string) (*Secret, error) {
	c.logger.Debug("getting secret", zap.String("path", path))

	secret, err := c.client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("reading secret: %w", err)
	}

	if secret == nil {
		return nil, ErrSecretNotFound
	}

	return &Secret{
		Path:    path,
		Data:    secret.Data,
		Version: 1, // Would extract from metadata
	}, nil
}
