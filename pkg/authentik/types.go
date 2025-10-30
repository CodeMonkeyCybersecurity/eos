/* pkg/authentik/types.go */

package authentik

import (
	"context"
	"fmt"
)

// Deprecated: Use AuthentikClient or APIClient instead
// This type is kept for backward compatibility but delegates to APIClient
type Client struct {
	apiClient *APIClient
}

// NewDeprecatedClient creates a Client that wraps APIClient
// Deprecated: Use NewClient (which returns *APIClient) instead
func NewDeprecatedClient(baseURL, token string) *Client {
	return &Client{
		apiClient: NewClient(baseURL, token),
	}
}

// Get performs a GET request
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	return c.apiClient.APICall(ctx, path)
}

// Post performs a POST request
func (c *Client) Post(ctx context.Context, path string, body interface{}) ([]byte, error) {
	// TODO: Implement POST method in APIClient
	return nil, fmt.Errorf("POST not implemented in deprecated Client")
}

// Patch performs a PATCH request
func (c *Client) Patch(ctx context.Context, path string, body interface{}) ([]byte, error) {
	// TODO: Implement PATCH method in APIClient
	return nil, fmt.Errorf("PATCH not implemented in deprecated Client")
}

// DoRequest performs an HTTP request
func (c *Client) DoRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	// TODO: Implement DoRequest method in APIClient
	return nil, fmt.Errorf("DoRequest not implemented in deprecated Client")
}

// ClientType represents the type of authentication client
type ClientType string

const (
	ClientTypeAuthentik ClientType = "authentik"
)

// AuthClient provides a unified interface for authentication clients
type AuthClient interface {
	GroupExists(groupName string) (bool, error)
	CreateGroup(groupName string) error
	AddUserToGroup(username, groupName string) error
}

// AuthClientWithUser extends AuthClient with user operations
type AuthClientWithUser interface {
	AuthClient
	GetUserByUsername(username string) (interface{}, error)
}
