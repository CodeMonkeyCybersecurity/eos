// pkg/vault/util_auth_approle.go

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// LoginAppRole authenticates to Vault using stored RoleID and SecretID.
func LoginAppRole() (*api.Client, error) {
	client, err := NewClient() // or your GetVaultClient helper
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

	zap.L().Info("✅ Successfully authenticated with Vault using AppRole")
	return client, nil
}

func readAppRoleCredsFromDisk() (string, string, error) {
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

	zap.L().Info("📄 Loaded AppRole credentials from disk",
		zap.String("role_id_path", shared.RoleIDPath),
		zap.String("secret_id_path", shared.SecretIDPath),
	)
	return roleID, secretID, nil
}

// PhaseCreateAppRole creates the EOS AppRole and saves credentials.
func PhaseCreateAppRole(client *api.Client, log *zap.Logger, opts shared.AppRoleOptions) (string, string, error) {
	zap.L().Info("🔑 [Phase 10] Creating AppRole for EOS")

	roleID, secretID, err := EnsureAppRole(client, opts)
	if err != nil {
		zap.L().Error("❌ Failed to ensure AppRole", zap.Error(err))
		return "", "", fmt.Errorf("ensure AppRole: %w", err)
	}

	zap.L().Info("✅ AppRole provisioning complete 🎉")
	return roleID, secretID, nil
}

// WriteAppRoleFiles writes the Vault AppRole role_id and secret_id to disk with secure permissions.
func WriteAppRoleFiles(roleID, secretID string) error {
	dir := filepath.Dir(shared.RoleIDPath)
	zap.L().Info("📁 Ensuring AppRole directory", zap.String("path", dir))
	if err := system.EnsureOwnedDir(dir, 0o700, shared.EosUser); err != nil {
		return err
	}

	pairs := map[string]string{
		shared.RoleIDPath:   roleID + "\n",
		shared.SecretIDPath: secretID + "\n",
	}
	for path, data := range pairs {
		zap.L().Debug("✏️  Writing AppRole file", zap.String("path", path))
		if err := system.WriteOwnedFile(path, []byte(data), 0o600, shared.EosUser); err != nil {
			return err
		}
	}

	zap.L().Info("✅ AppRole credentials written",
		zap.String("role_file", shared.RoleIDPath),
		zap.String("secret_file", shared.SecretIDPath))
	return nil
}

// refreshAppRoleCreds retrieves fresh credentials but does NOT write files.
func refreshAppRoleCreds(client *api.Client) (string, string, error) {
	zap.L().Debug("🔑 Requesting fresh AppRole credentials")

	roleResp, err := client.Logical().Read(shared.RolePath + "/role-id")
	if err != nil {
		return "", "", fmt.Errorf("read role_id: %w", err)
	}
	roleID, ok := roleResp.Data["role_id"].(string)
	if !ok || roleID == "" {
		return "", "", fmt.Errorf("invalid role_id in Vault response")
	}

	secretResp, err := client.Logical().Write(shared.RolePath+"/secret-id", nil)
	if err != nil {
		return "", "", fmt.Errorf("generate secret_id: %w", err)
	}
	secretID, ok := secretResp.Data["secret_id"].(string)
	if !ok || secretID == "" {
		return "", "", fmt.Errorf("invalid secret_id in Vault response")
	}

	return roleID, secretID, nil
}

// EnsureAppRole provisions the AppRole if missing or refreshes credentials if needed.
func EnsureAppRole(client *api.Client, opts shared.AppRoleOptions) (string, string, error) {
	if !opts.ForceRecreate {
		if _, err := os.Stat(shared.RoleIDPath); err == nil {
			zap.L().Info("🔐 AppRole credentials already exist", zap.String("path", shared.RoleIDPath))
			if opts.RefreshCreds {
				return refreshAppRoleCreds(client)
			}
			return readAppRoleCredsFromDisk()
		}
	}

	zap.L().Info("🛠 Creating Vault AppRole", zap.String("role", shared.RoleName))

	if err := EnableAppRoleAuth(client); err != nil {
		return "", "", fmt.Errorf("enable AppRole auth: %w", err)
	}

	roleData := map[string]interface{}{
		"policies":      []string{shared.EosVaultPolicy},
		"token_ttl":     shared.VaultDefaultTokenTTL,
		"token_max_ttl": shared.VaultDefaultTokenMaxTTL,
		"secret_id_ttl": shared.VaultDefaultSecretIDTTL,
	}
	if _, err := client.Logical().Write(shared.RolePath, roleData); err != nil {
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

// DefaultAppRoleOptions returns the default settings used when creating the eos-approle in Vault.
func DefaultAppRoleOptions() shared.AppRoleOptions {
	return shared.AppRoleOptions{
		RoleName:      shared.EosID,
		Policies:      []string{shared.EosVaultPolicy},
		TokenTTL:      "1h",
		TokenMaxTTL:   "4h",
		SecretIDTTL:   "24h",
		ForceRecreate: false,
		RefreshCreds:  false,
	}
}
