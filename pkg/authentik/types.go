/* pkg/authentik/types.go */

package authentik

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
)

// Deprecated: Use AuthentikClient instead
type Client struct {
	_ *gocloak.GoCloak // Removed unused field client
	_ *gocloak.JWT     // Removed unused field token
	_ string           // Removed unused field realm
	_ context.Context  // Removed unused field ctx
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
