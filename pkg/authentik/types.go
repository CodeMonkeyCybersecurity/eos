/* pkg/authentik/types.go */

package authentik

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
)

// Deprecated: Use AuthentikClient instead
type Client struct {
	client *gocloak.GoCloak
	token  *gocloak.JWT
	realm  string
	ctx    context.Context
}

// ClientType represents the type of authentication client
type ClientType string

const (
	ClientTypeKeycloak  ClientType = "keycloak"  // Deprecated
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
