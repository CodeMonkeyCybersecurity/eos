// pkg/vault/client.go
//
// HashiCorp Vault Client Management
//
// This package provides comprehensive HashiCorp Vault integration for EOS with
// safe, high-quality and effective security features. It implements the core
// Vault client functionality with proper authentication, error handling, and
// security controls.
//
// Key Features:
// - Secure client creation and connection management
// - TLS encryption with strong cipher suites
// - Comprehensive error handling with context
// - Structured logging for audit and debugging
// - Token management and renewal
// - Authentication method configuration
//
// Security Features:
// - Multi-factor authentication (TOTP, Duo, PingID, Okta)
// - Role-based access control with principle of least privilege
// - Comprehensive system hardening (swap/coredump disabling, firewall config)
// - Secure initialization data access with audit logging
// - Automatic sensitive data redaction in logs
//
// Usage:
//   client, err := vault.NewClient("https://vault.example.com:8200", logger)
//   if err != nil {
//       // Handle error
//   }
//   
//   // Use client for Vault operations
//   secret, err := client.ReadSecret(ctx, "secret/myapp")
//
// Integration:
// This client integrates with EOS CLI commands:
// - eos create vault    # Install Vault
// - eos enable vault    # Interactive setup with MFA
// - eos secure vault    # Apply comprehensive hardening
// - eos read vault-init # Secure access to initialization data
//
// Configuration:
// Vault configuration uses secure defaults with TLS encryption, file storage
// backend, comprehensive logging, and UI enabled for administration.
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
