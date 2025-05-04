// pkg/vault/util_auth.go

package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func Auth() (*api.Client, error) {
	client, err := GetVaultClient()
	if err != nil {
		zap.L().Warn("⚠️ Vault client unavailable", zap.Error(err))
		return nil, err
	}

	if err := OrchestrateVaultAuth(client); err != nil {
		zap.L().Warn("⚠️ Vault authentication failed", zap.Error(err))
		return nil, err
	}

	ValidateAndCache(client)
	SetVaultClient(client)
	return client, nil
}

func OrchestrateVaultAuth(client *api.Client) error {
	authMethods := []struct {
		name string
		fn   func(*api.Client) (string, error)
	}{
		{"agent token", tryAgentToken},
		{"AppRole", tryAppRole},
		{"disk token file", tryTokenFile},   // renamed for clarity
		{"userpass", tryUserpassWithPrompt}, // wrap userpass with y/N check
		{"root token file", tryRootTokenFile},
		{"prompt root token", promptRootToken},
	}

	for _, method := range authMethods {
		zap.L().Info(fmt.Sprintf("🔑 Trying %s", method.name))
		token, err := method.fn(client)
		if err != nil {
			zap.L().Warn(fmt.Sprintf("⚠️ %s failed", method.name), zap.Error(err))
			continue
		}

		zap.L().Debug(fmt.Sprintf("✅ %s returned token candidate: %s", method.name, token))

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
	path := "/etc/vault-agent-eos.token"
	zap.L().Debug("📂 Reading agent token", zap.String("path", path))
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read agent token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	zap.L().Debug("🔑 Agent token read successfully")
	return token, nil
}

func tryAppRole(client *api.Client) (string, error) {
	zap.L().Debug("📂 Reading AppRole credentials from disk")
	roleID, secretID, err := readAppRoleCredsFromDisk()
	if err != nil {
		return "", fmt.Errorf("read AppRole creds: %w", err)
	}
	zap.L().Debug("🔑 AppRole creds loaded, attempting login", zap.String("roleID", roleID))
	secret, err := client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil || secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("approle login failed: %w", err)
	}
	zap.L().Debug("✅ AppRole login successful")
	return secret.Auth.ClientToken, nil
}

func tryTokenFile(_ *api.Client) (string, error) {
	path := "/var/lib/eos/secrets/vault.token"
	zap.L().Debug("📂 Reading token file", zap.String("path", path))
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	zap.L().Debug("🔑 Token file read successfully")
	return token, nil
}

func tryUserpassWithPrompt(client *api.Client) (string, error) {
	if !interaction.PromptYesNo("Is userpass authentication enabled?", false) {
		zap.L().Info("⏭️ Skipping userpass (user chose 'no')")
		return "", fmt.Errorf("userpass skipped by user")
	}
	return tryUserpass(client)
}

func tryUserpass(client *api.Client) (string, error) {
	zap.L().Info("🔑 Prompting user for username and password")
	usernames, err := interaction.PromptSecrets("Username", 1)
	if err != nil {
		return "", fmt.Errorf("prompt username: %w", err)
	}
	passwords, err := interaction.PromptSecrets("Password", 1)
	if err != nil {
		return "", fmt.Errorf("prompt password: %w", err)
	}

	username := usernames[0]
	password := passwords[0]
	zap.L().Debug("🔐 Attempting userpass login", zap.String("username", username))
	secret, err := client.Logical().Write(fmt.Sprintf("auth/userpass/login/%s", username), map[string]interface{}{
		"password": password,
	})
	if err != nil || secret == nil || secret.Auth == nil {
		return "", fmt.Errorf("userpass login failed: %w", err)
	}
	zap.L().Debug("✅ Userpass login successful")
	return secret.Auth.ClientToken, nil
}

func tryRootTokenFile(_ *api.Client) (string, error) {
	path := "/var/lib/eos/secrets/root.token"
	zap.L().Debug("📂 Reading root token file", zap.String("path", path))
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read root token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	zap.L().Debug("🔑 Root token file read successfully")
	return token, nil
}

func promptRootToken(_ *api.Client) (string, error) {
	zap.L().Info("🔑 Please enter the Vault root token")
	tokens, err := interaction.PromptSecrets("Root Token", 1)
	if err != nil {
		return "", fmt.Errorf("prompt root token: %w", err)
	}
	zap.L().Debug("🔑 Root token entered by user")
	return tokens[0], nil
}

func VerifyRootToken(client *api.Client, token string) error {
	zap.L().Debug("🔍 Verifying token by calling LookupSelf")
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
	zap.L().Debug("✅ Token verified successfully")
	return true
}
