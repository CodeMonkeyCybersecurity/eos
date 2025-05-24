// pkg/vault/auth_approle.go
package vault

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debian"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"go.uber.org/zap"
)

// LoginAppRole authenticates to Vault using stored RoleID and SecretID.
func LoginAppRole() (*api.Client, error) {
	client, err := NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	roleID, secretID, err := readAppRoleCredsFromDisk(client)
	if err != nil {
		return nil, fmt.Errorf("failed to read AppRole creds: %w", err)
	}

	auth, err := approle.NewAppRoleAuth(roleID, &approle.SecretID{
		FromString: secretID,
	}, approle.WithMountPath("auth/approle"))
	if err != nil {
		return nil, fmt.Errorf("create approle auth: %w", err)
	}

	secret, err := client.Auth().Login(context.Background(), auth)
	if err != nil {
		return nil, fmt.Errorf("approle login failed: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return nil, fmt.Errorf("no auth info returned from Vault approle login")
	}

	client.SetToken(secret.Auth.ClientToken)
	zap.L().Info("✅ Successfully authenticated with Vault using AppRole")
	return client, nil
}

func readAppRoleCredsFromDisk(client *api.Client) (string, string, error) {
	roleIDBytes, err := os.ReadFile(shared.AppRolePaths.RoleID)
	if err != nil {
		return "", "", fmt.Errorf("read role_id from disk: %w", err)
	}
	roleID := strings.TrimSpace(string(roleIDBytes))

	secretIDBytes, err := os.ReadFile(shared.AppRolePaths.SecretID)
	if err != nil {
		return "", "", fmt.Errorf("read secret_id from disk: %w", err)
	}
	secretIDRaw := strings.TrimSpace(string(secretIDBytes))

	if strings.HasPrefix(secretIDRaw, "s.") {
		zap.L().Info("🔐 Detected wrapped SecretID token — unwrapping")
		secret, err := client.Logical().Unwrap(secretIDRaw)
		if err != nil {
			return "", "", fmt.Errorf("failed to unwrap secret_id: %w", err)
		}
		if secret == nil || secret.Data == nil {
			return "", "", fmt.Errorf("unwrapped SecretID is empty")
		}
		sid, ok := secret.Data["secret_id"].(string)
		if !ok {
			return "", "", fmt.Errorf("unwrapped SecretID is malformed")
		}
		return roleID, sid, nil
	}

	zap.L().Warn("⚠️ SecretID is stored in plaintext. Consider using response wrapping.")
	return roleID, secretIDRaw, nil
}

func PhaseCreateAppRole(client *api.Client, log *zap.Logger, opts shared.AppRoleOptions) (string, string, error) {
	log.Info("🔑 [Phase 10] Creating AppRole for EOS")
	roleID, secretID, err := EnsureAppRole(client, opts)
	if err != nil {
		log.Error("❌ Failed to ensure AppRole", zap.Error(err))
		return "", "", fmt.Errorf("ensure AppRole: %w", err)
	}
	log.Info("✅ AppRole provisioning complete 🎉")
	return roleID, secretID, nil
}

func WriteAppRoleFiles(roleID, secretID string) error {
	dir := filepath.Dir(shared.AppRolePaths.RoleID)
	zap.L().Info("📁 Ensuring AppRole directory", zap.String("path", dir))
	if err := debian.EnsureOwnedDir(dir, 0o700, shared.EosID); err != nil {
		return err
	}

	pairs := map[string]string{
		shared.AppRolePaths.RoleID:   roleID + "\n",
		shared.AppRolePaths.SecretID: secretID + "\n",
	}
	for path, data := range pairs {
		zap.L().Debug("✏️  Writing AppRole file", zap.String("path", path))
		if err := debian.WriteOwnedFile(path, []byte(data), 0o600, shared.EosID); err != nil {
			return err
		}
	}

	zap.L().Info("✅ AppRole credentials written",
		zap.String("role_file", shared.AppRolePaths.RoleID),
		zap.String("secret_file", shared.AppRolePaths.SecretID))
	return nil
}

func refreshAppRoleCreds(client *api.Client) (string, string, error) {
	zap.L().Debug("🔑 Requesting fresh AppRole credentials")
	roleResp, err := client.Logical().Read(shared.AppRoleRoleIDPath)
	if err != nil {
		return "", "", fmt.Errorf("read role_id: %w", err)
	}
	roleID, ok := roleResp.Data["role_id"].(string)
	if !ok || roleID == "" {
		return "", "", fmt.Errorf("invalid role_id in Vault response")
	}

	secretResp, err := client.Logical().Write(shared.AppRoleSecretIDPath, nil)
	if err != nil {
		return "", "", fmt.Errorf("generate secret_id: %w", err)
	}
	secretID, ok := secretResp.Data["secret_id"].(string)
	if !ok || secretID == "" {
		return "", "", fmt.Errorf("invalid secret_id in Vault response")
	}
	return roleID, secretID, nil
}

func EnsureAppRole(client *api.Client, opts shared.AppRoleOptions) (string, string, error) {
	if !opts.ForceRecreate {
		if _, err := os.Stat(shared.AppRolePaths.RoleID); err == nil {
			zap.L().Info("🔐 AppRole credentials already exist", zap.String("path", shared.AppRolePaths.RoleID))
			if opts.RefreshCreds {
				return refreshAppRoleCreds(client)
			}
			return readAppRoleCredsFromDisk(client)
		}
	}

	zap.L().Info("🛠 Creating Vault AppRole", zap.String("role", shared.AppRoleName))
	if err := EnableAppRoleAuth(client); err != nil {
		return "", "", fmt.Errorf("enable AppRole auth: %w", err)
	}

	roleData := shared.DefaultAppRoleData
	if _, err := client.Logical().Write(shared.AppRolePath, roleData); err != nil {
		return "", "", fmt.Errorf("write AppRole: %w", err)
	}
	zap.L().Info("✅ AppRole written")

	roleID, secretID, err := refreshAppRoleCreds(client)
	if err != nil {
		return "", "", fmt.Errorf("fetch AppRole creds: %w", err)
	}

	if err := WriteAppRoleFiles(roleID, secretID); err != nil {
		return "", "", fmt.Errorf("write AppRole files: %w", err)
	}
	return roleID, secretID, nil
}

func EnableAppRoleAuth(client *api.Client) error {
	zap.L().Info("📡 Enabling AppRole auth method if needed...")
	err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{Type: "approle"})
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "path is already in use") {
		zap.L().Warn("⚠️ AppRole auth method may already be enabled", zap.Error(err))
		return nil
	}
	zap.L().Error("❌ Failed to enable AppRole auth method", zap.Error(err))
	return fmt.Errorf("enable approle auth: %w", err)
}
