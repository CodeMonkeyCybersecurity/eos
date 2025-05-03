package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// OrchestrateVaultAuth tries all fallback methods and sets client token.
func OrchestrateVaultAuth(client *api.Client) error {
	authMethods := []struct {
		name string
		fn   func(*api.Client) (string, error)
	}{
		{"agent token", tryAgentToken},
		{"AppRole", tryAppRole},
		{"token file", tryTokenFile},
		{"prompt root token", promptRootToken},
	}

	for _, method := range authMethods {
		zap.L().Info(fmt.Sprintf("🔑 Trying %s", method.name))
		token, err := method.fn(client)
		if err != nil {
			zap.L().Warn(fmt.Sprintf("⚠️ %s failed", method.name), zap.Error(err))
			continue
		}

		if verifyToken(client, token) {
			SetVaultToken(client, token)
			zap.L().Info(fmt.Sprintf("✅ Authenticated using %s", method.name))
			return nil
		}

		zap.L().Warn(fmt.Sprintf("❌ %s verification failed", method.name))
	}

	return fmt.Errorf("all authentication methods failed")
}

func tryAgentToken(_ *api.Client) (string, error) {
	data, err := os.ReadFile("/etc/vault-agent-eos.token")
	if err != nil {
		return "", fmt.Errorf("read agent token: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func tryAppRole(client *api.Client) (string, error) {
	roleID, secretID, err := readAppRoleCredsFromDisk()
	if err != nil {
		return "", err
	}
	secret, err := client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil || secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("approle login failed: %w", err)
	}
	return secret.Auth.ClientToken, nil
}

func tryTokenFile(_ *api.Client) (string, error) {
	data, err := os.ReadFile("/var/lib/eos/secrets/vault.token")
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func promptRootToken(_ *api.Client) (string, error) {
	zap.L().Info("🔑 Please enter the Vault root token")
	tokens, err := interaction.PromptSecrets("Root Token", 1)
	if err != nil {
		return "", err
	}
	return tokens[0], nil
}

func VerifyRootToken(client *api.Client, token string) error {
	client.SetToken(token)
	secret, err := client.Auth().Token().LookupSelf()
	if err != nil || secret == nil {
		return fmt.Errorf("token validation failed: %w", err)
	}
	return nil
}

func verifyToken(client *api.Client, token string) bool {
	if err := VerifyRootToken(client, token); err != nil {
		zap.L().Warn("❌ Token verification failed", zap.Error(err))
		return false
	}
	return true
}
