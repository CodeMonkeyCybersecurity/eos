// pkg/vault/phase15_harden.go

package vault

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func RevokeRootToken(client *api.Client, token string, log *zap.Logger) error {
	client.SetToken(token)

	err := client.Auth().Token().RevokeSelf("")
	if err != nil {
		return fmt.Errorf("failed to revoke root token: %w", err)
	}

	log.Info("✅ Root token revoked")
	return nil
}
