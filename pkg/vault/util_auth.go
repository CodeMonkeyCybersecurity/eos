package vault

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
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
		{"agent token", readTokenFile("/etc/vault-agent-eos.token")},
		{"AppRole", tryAppRole},
		{"disk token file", readTokenFile("/var/lib/eos/secrets/vault.token")},
		{"userpass", tryUserpassWithPrompt},
		{"root token file", tryRootToken},
	}

	for _, m := range authMethods {
		zap.L().Info("🔑 Trying auth method", zap.String("method", m.name))
		token, err := m.fn(client)
		if err != nil {
			zap.L().Warn("⚠️ Auth method failed", zap.String("method", m.name), zap.Error(err))
			continue
		}
		zap.L().Debug("✅ Auth method returned token candidate", zap.String("method", m.name))
		if VerifyToken(client, token) {
			SetVaultToken(client, token)
			zap.L().Info("✅ Authenticated using method", zap.String("method", m.name))
			return nil
		}
	}
	errMsg := "all authentication methods failed"
	zap.L().Error(errMsg)
	return errors.New(errMsg)
}

func readTokenFile(path string) func(*api.Client) (string, error) {
	return func(_ *api.Client) (string, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			zap.L().Warn("❌ Failed to read token file", zap.String("path", path), zap.Error(err))
			return "", fmt.Errorf("read token file %s: %w", path, err)
		}
		token := strings.TrimSpace(string(data))
		zap.L().Debug("🔑 Token file read successfully", zap.String("path", path))
		return token, nil
	}
}

func tryAppRole(client *api.Client) (string, error) {
	roleID, secretID, err := readAppRoleCredsFromDisk()
	if err != nil {
		zap.L().Warn("❌ Failed to read AppRole credentials", zap.Error(err))
		return "", fmt.Errorf("read AppRole creds: %w", err)
	}
	secret, err := client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id": roleID, "secret_id": secretID,
	})
	if err != nil || secret == nil || secret.Auth == nil {
		zap.L().Warn("❌ AppRole login failed", zap.Error(err))
		return "", fmt.Errorf("approle login failed: %w", err)
	}
	zap.L().Debug("✅ AppRole login successful", zap.String("roleID", roleID))
	return secret.Auth.ClientToken, nil
}

func tryUserpassWithPrompt(client *api.Client) (string, error) {
	if !interaction.PromptYesNo("Is userpass authentication enabled?", false) {
		zap.L().Info("⏭️ Skipping userpass (user chose 'no')")
		return "", errors.New("userpass skipped by user")
	}
	return tryUserpass(client)
}

func tryUserpass(client *api.Client) (string, error) {
	usernames, err := interaction.PromptSecrets("Username", 1)
	if err != nil {
		zap.L().Warn("❌ Failed to prompt username", zap.Error(err))
		return "", fmt.Errorf("prompt username: %w", err)
	}
	passwords, err := interaction.PromptSecrets("Password", 1)
	if err != nil {
		zap.L().Warn("❌ Failed to prompt password", zap.Error(err))
		return "", fmt.Errorf("prompt password: %w", err)
	}
	username, password := usernames[0], passwords[0]
	secret, err := client.Logical().Write(fmt.Sprintf("auth/userpass/login/%s", username),
		map[string]interface{}{"password": password})
	if err != nil || secret == nil || secret.Auth == nil {
		zap.L().Warn("❌ Userpass login failed", zap.String("username", username), zap.Error(err))
		return "", fmt.Errorf("userpass login failed: %w", err)
	}
	zap.L().Debug("✅ Userpass login successful", zap.String("username", username))
	return secret.Auth.ClientToken, nil
}

func tryRootToken(_ *api.Client) (string, error) {
	initRes, err := LoadOrPromptInitResult()
	if err != nil {
		zap.L().Warn("❌ Failed to load or prompt init result", zap.Error(err))
		return "", fmt.Errorf("load or prompt init result: %w", err)
	}
	if strings.TrimSpace(initRes.RootToken) == "" {
		errMsg := "root token is missing in init result"
		zap.L().Warn(errMsg)
		return "", errors.New(errMsg)
	}
	zap.L().Debug("✅ Root token loaded successfully")
	return initRes.RootToken, nil
}

func LoadOrPromptInitResult() (*api.InitResponse, error) {
	var res api.InitResponse
	if err := ReadFallbackJSON(shared.VaultInitPath, &res); err != nil {
		zap.L().Warn("⚠️ Fallback file missing, prompting user", zap.Error(err))
		return PromptForInitResult()
	}
	if err := VerifyInitResult(&res); err != nil {
		zap.L().Warn("⚠️ Loaded init result invalid, prompting user", zap.Error(err))
		return PromptForInitResult()
	}
	return &res, nil
}

func VerifyInitResult(r *api.InitResponse) error {
	if r == nil {
		err := errors.New("init result is nil")
		zap.L().Warn("❌ Invalid init result", zap.Error(err))
		return err
	}
	if len(r.KeysB64) < 3 {
		err := fmt.Errorf("expected at least 3 unseal keys, got %d", len(r.KeysB64))
		zap.L().Warn("❌ Invalid init result", zap.Error(err))
		return err
	}
	if strings.TrimSpace(r.RootToken) == "" {
		err := errors.New("root token is missing or empty")
		zap.L().Warn("❌ Invalid init result", zap.Error(err))
		return err
	}
	return nil
}

func VerifyRootToken(client *api.Client, token string) error {
	client.SetToken(token)
	secret, err := client.Auth().Token().LookupSelf()
	if err != nil || secret == nil {
		zap.L().Warn("❌ Token validation failed", zap.Error(err))
		return fmt.Errorf("token validation failed: %w", err)
	}
	zap.L().Debug("✅ Token validated successfully")
	return nil
}

func VerifyToken(client *api.Client, token string) bool {
	err := VerifyRootToken(client, token)
	if err != nil {
		zap.L().Warn("❌ Token verification failed", zap.Error(err))
		return false
	}
	zap.L().Debug("✅ Token verified successfully")
	return true
}
