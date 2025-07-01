// pkg/infrastructure/vault/client.go
package vault

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
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
		return vault.ErrVaultSealed
	}

	return nil
}

// GetSecret implements VaultService.GetSecret
func (c *Client) GetSecret(ctx context.Context, path string) (*vault.Secret, error) {
	c.logger.Debug("getting secret", zap.String("path", path))

	secret, err := c.client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("reading secret: %w", err)
	}

	if secret == nil {
		return nil, vault.ErrSecretNotFound
	}

	return &vault.Secret{
		Path:    path,
		Data:    secret.Data,
		Version: 1, // Would extract from metadata
	}, nil
}
