// pkg/vault/util_auth_approle.go

package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// LoginAppRole authenticates to Vault using stored RoleID and SecretID.
func LoginAppRole(log *zap.Logger) (*api.Client, error) {
	client, err := NewClient(log) // or your GetVaultClient helper
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	roleID, err := os.ReadFile(shared.RoleIDPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read role_id file: %w", err)
	}

	secretID, err := os.ReadFile(shared.SecretIDPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret_id file: %w", err)
	}

	secret, err := client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   strings.TrimSpace(string(roleID)),
		"secret_id": strings.TrimSpace(string(secretID)),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with approle: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return nil, fmt.Errorf("no auth info returned from Vault approle login")
	}

	// Set the client token
	client.SetToken(secret.Auth.ClientToken)

	log.Info("✅ Successfully authenticated with Vault using AppRole")
	return client, nil
}

func readAppRoleCredsFromDisk(log *zap.Logger) (string, string, error) {
	roleIDBytes, err := os.ReadFile(shared.RoleIDPath)
	if err != nil {
		return "", "", fmt.Errorf("read role_id from disk: %w", err)
	}
	secretIDBytes, err := os.ReadFile(shared.SecretIDPath)
	if err != nil {
		return "", "", fmt.Errorf("read secret_id from disk: %w", err)
	}
	roleID := strings.TrimSpace(string(roleIDBytes))
	secretID := strings.TrimSpace(string(secretIDBytes))

	log.Info("📄 Loaded AppRole credentials from disk",
		zap.String("role_id_path", shared.RoleIDPath),
		zap.String("secret_id_path", shared.SecretIDPath),
	)
	return roleID, secretID, nil
}
