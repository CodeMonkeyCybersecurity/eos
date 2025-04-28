// pkg/vault/phase8_validate_root_token.go

package vault

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// SetVaultToken configures the Vault client to use a provided token.
func SetVaultToken(client *api.Client, token string) {
	client.SetToken(token)
}

// GetPrivilegedVaultClient returns a Vault client authenticated as 'eos' system user
func GetPrivilegedVaultClient(log *zap.Logger) (*api.Client, error) {
	token, err := readTokenFromSink(shared.VaultAgentTokenPath)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(log)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	return client, nil
}
