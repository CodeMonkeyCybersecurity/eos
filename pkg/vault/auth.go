package vault

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func Authn(rc *eos_io.RuntimeContext) (*api.Client, error) {
	client, err := GetVaultClient(rc)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ Vault client unavailable", zap.Error(err))
		return nil, err
	}

	if err := OrchestrateVaultAuth(rc, client); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ Vault authentication failed", zap.Error(err))
		return nil, err
	}

	ValidateAndCache(rc, client)
	SetVaultClient(rc, client)
	return client, nil
}

func OrchestrateVaultAuth(rc *eos_io.RuntimeContext, client *api.Client) error {
	authMethods := []struct {
		name string
		fn   func(*api.Client) (string, error)
	}{
		{"agent token", readTokenFile(rc, "/etc/vault-agent-eos.token")},
		{"AppRole", func(client *api.Client) (string, error) { return tryAppRole(rc, client) }},
		{"disk token file", readTokenFile(rc, "/var/lib/eos/secrets/token")},
		{"userpass", func(client *api.Client) (string, error) { return tryUserpassWithPrompt(rc, client) }},
		{"root token file", func(client *api.Client) (string, error) { return tryRootToken(rc, client) }},
	}

	for _, m := range authMethods {
		otelzap.Ctx(rc.Ctx).Info("🔑 Trying auth method", zap.String("method", m.name))
		token, err := m.fn(client)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Warn("⚠️ Auth method failed", zap.String("method", m.name), zap.Error(err))
			continue
		}
		otelzap.Ctx(rc.Ctx).Debug("✅ Auth method returned token candidate", zap.String("method", m.name))
		if VerifyToken(rc, client, token) {
			SetVaultToken(rc, client, token)
			otelzap.Ctx(rc.Ctx).Info("✅ Authenticated using method", zap.String("method", m.name))
			return nil
		}
	}
	errMsg := "all authentication methods failed"
	otelzap.Ctx(rc.Ctx).Error(errMsg)
	return errors.New(errMsg)
}

func readTokenFile(rc *eos_io.RuntimeContext, path string) func(*api.Client) (string, error) {
	return func(_ *api.Client) (string, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Warn("❌ Failed to read token file", zap.String("path", path), zap.Error(err))
			return "", fmt.Errorf("read token file %s: %w", path, err)
		}
		token := strings.TrimSpace(string(data))
		otelzap.Ctx(rc.Ctx).Debug("🔑 Token file read successfully", zap.String("path", path))
		return token, nil
	}
}

func tryAppRole(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
	roleID, secretID, err := readAppRoleCredsFromDisk(rc, client)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("❌ Failed to read AppRole credentials", zap.Error(err))
		return "", fmt.Errorf("read AppRole creds: %w", err)
	}
	secret, err := client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id": roleID, "secret_id": secretID,
	})
	if err != nil || secret == nil || secret.Auth == nil {
		otelzap.Ctx(rc.Ctx).Warn("❌ AppRole login failed", zap.Error(err))
		return "", fmt.Errorf("approle login failed: %w", err)
	}
	otelzap.Ctx(rc.Ctx).Debug("✅ AppRole login successful", zap.String("roleID", roleID))
	return secret.Auth.ClientToken, nil
}

func tryUserpassWithPrompt(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
	if !interaction.PromptYesNo(rc.Ctx, "Is userpass authentication enabled?", false) {
		otelzap.Ctx(rc.Ctx).Info("⏭️ Skipping userpass (user chose 'no')")
		return "", errors.New("userpass skipped by user")
	}
	return tryUserpass(rc, client)
}

func tryUserpass(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
	usernames, err := interaction.PromptSecrets(rc.Ctx, "Username", 1)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("❌ Failed to prompt username", zap.Error(err))
		return "", fmt.Errorf("prompt username: %w", err)
	}
	passwords, err := interaction.PromptSecrets(rc.Ctx, "Password", 1)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("❌ Failed to prompt password", zap.Error(err))
		return "", fmt.Errorf("prompt password: %w", err)
	}
	username, password := usernames[0], passwords[0]
	secret, err := client.Logical().Write(fmt.Sprintf("auth/userpass/login/%s", username),
		map[string]interface{}{"password": password})
	if err != nil || secret == nil || secret.Auth == nil {
		otelzap.Ctx(rc.Ctx).Warn("❌ Userpass login failed", zap.String("username", username), zap.Error(err))
		return "", fmt.Errorf("userpass login failed: %w", err)
	}
	otelzap.Ctx(rc.Ctx).Debug("✅ Userpass login successful", zap.String("username", username))
	return secret.Auth.ClientToken, nil
}

func tryRootToken(rc *eos_io.RuntimeContext, _ *api.Client) (string, error) {
	initRes, err := LoadOrPromptInitResult(rc)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("❌ Failed to load or prompt init result", zap.Error(err))
		return "", fmt.Errorf("load or prompt init result: %w", err)
	}
	if strings.TrimSpace(initRes.RootToken) == "" {
		errMsg := "root token is missing in init result"
		otelzap.Ctx(rc.Ctx).Warn(errMsg)
		return "", errors.New(errMsg)
	}
	otelzap.Ctx(rc.Ctx).Debug("✅ Root token loaded successfully")
	return initRes.RootToken, nil
}

func LoadOrPromptInitResult(rc *eos_io.RuntimeContext) (*api.InitResponse, error) {
	var res api.InitResponse
	if err := ReadFallbackJSON(shared.VaultInitPath, &res); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ Fallback file missing, prompting user", zap.Error(err))
		return PromptForInitResult(rc)
	}
	if err := VerifyInitResult(rc, &res); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ Loaded init result invalid, prompting user", zap.Error(err))
		return PromptForInitResult(rc)
	}
	return &res, nil
}

func VerifyInitResult(rc *eos_io.RuntimeContext, r *api.InitResponse) error {
	if r == nil {
		err := errors.New("init result is nil")
		otelzap.Ctx(rc.Ctx).Warn("❌ Invalid init result", zap.Error(err))
		return err
	}
	if len(r.KeysB64) < 3 {
		err := fmt.Errorf("expected at least 3 unseal keys, got %d", len(r.KeysB64))
		otelzap.Ctx(rc.Ctx).Warn("❌ Invalid init result", zap.Error(err))
		return err
	}
	if strings.TrimSpace(r.RootToken) == "" {
		err := errors.New("root token is missing or empty")
		otelzap.Ctx(rc.Ctx).Warn("❌ Invalid init result", zap.Error(err))
		return err
	}
	return nil
}

func VerifyRootToken(rc *eos_io.RuntimeContext, client *api.Client, token string) error {
	client.SetToken(token)
	secret, err := client.Auth().Token().LookupSelf()
	if err != nil || secret == nil {
		otelzap.Ctx(rc.Ctx).Warn("❌ Token validation failed", zap.Error(err))
		return fmt.Errorf("token validation failed: %w", err)
	}
	otelzap.Ctx(rc.Ctx).Debug("✅ Token validated successfully")
	return nil
}

func VerifyToken(rc *eos_io.RuntimeContext, client *api.Client, token string) bool {
	err := VerifyRootToken(rc, client, token)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("❌ Token verification failed", zap.Error(err))
		return false
	}
	otelzap.Ctx(rc.Ctx).Debug("✅ Token verified successfully")
	return true
}

type AppRoleLoginInput struct {
	RoleID      string
	SecretID    string
	MountPath   string
	UseWrapping bool // If true, use response-wrapped secret ID token
}

func buildSecretID(input AppRoleLoginInput) *approle.SecretID {
	return &approle.SecretID{
		FromString: input.SecretID,
	}
}

func buildAppRoleAuth(input AppRoleLoginInput) (*approle.AppRoleAuth, error) {
	opts := []approle.LoginOption{}

	if input.MountPath != "" {
		opts = append(opts, approle.WithMountPath(input.MountPath))
	}
	if input.UseWrapping {
		opts = append(opts, approle.WithWrappingToken())
	}

	auth, err := approle.NewAppRoleAuth(input.RoleID, buildSecretID(input), opts...)
	if err != nil {
		return nil, cerr.Wrap(err, "failed to create AppRoleAuth")
	}
	return auth, nil
}

func LoginWithAppRole(rc *eos_io.RuntimeContext, client *api.Client, input AppRoleLoginInput) (*api.Secret, error) {
	log := otelzap.Ctx(rc.Ctx)

	auth, err := buildAppRoleAuth(input)
	if err != nil {
		log.Error("❌ Failed to build AppRoleAuth", zap.Error(err))
		return nil, err
	}

	secret, err := client.Auth().Login(rc.Ctx, auth)
	if err != nil {
		log.Error("❌ AppRole login failed", zap.Error(err))
		return nil, cerr.Wrap(err, "Vault AppRole login failed")
	}

	if secret == nil || secret.Auth == nil {
		return nil, cerr.New("no secret or auth info returned by Vault")
	}

	log.Info("✅ Vault AppRole login successful")
	return secret, nil
}
