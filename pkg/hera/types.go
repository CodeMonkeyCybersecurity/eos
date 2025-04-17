/* pkg/hera/keycloak_types.go */

package hera

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
)

type Client struct {
	client *gocloak.GoCloak
	token  *gocloak.JWT
	realm  string
	ctx    context.Context
}
