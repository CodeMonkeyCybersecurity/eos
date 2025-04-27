// pkg/vault/phase10_create_approle.go

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

//--------------------------------------------------------------------
// 10. Create AppRole for EOS
//--------------------------------------------------------------------

// PhaseCreateAppRole(client, log, password)
// ├── DefaultAppRoleOptions()                    (setup options)
// ├── EnsureAppRole(client, log, opts)
// │   ├── os.Stat(shared.RoleIDPath)              (check if role_id file exists)
// │   ├── refreshAppRoleCreds(client, log)        (only if RefreshCreds=true)
// │   ├── EnableAppRoleAuth(client, log)          (if not enabled)
// │   │   ├── client.Sys().EnableAuthWithOptions() (vault API call to enable approle)
// │   ├── client.Logical().Write(shared.RolePath) (create/update role definition)
// │   ├── refreshAppRoleCreds(client, log)        (fetch fresh role_id, secret_id)
// │   │   ├── client.Logical().Read(role-id)
// │   │   ├── client.Logical().Write(secret-id)
// │   ├── WriteAppRoleFiles(roleID, secretID, log)
// │       ├── system.EnsureOwnedDir(path, 0700, eos)
// │       ├── system.WriteOwnedFile(role_id file, 0600, eos)
// │       ├── system.WriteOwnedFile(secret_id file, 0600, eos)
// ├── writeAgentPassword(password, log)            (only if password != "")
// │   ├── os.WriteFile(shared.VaultAgentPassPath, 0600)
// ├── WriteAgentSystemdUnit(log)                   (generate vault-agent-eos.service)
// ├── EnsureAgentServiceReady(log)
// │   ├── EnsureVaultAgentUnitExists(log)
// │   │   ├── os.Stat(shared.VaultAgentServicePath)
// │   │   ├── WriteAgentSystemdUnit(log) (if missing)
// │   ├── system.ReloadDaemonAndEnable(log, vault-agent-eos.service)
// └── log.Info("✅ AppRole provisioning complete")

// PhaseCreateAppRole creates the EOS AppRole and saves credentials.
func PhaseCreateAppRole(client *api.Client, log *zap.Logger, password string) (string, string, error) {
	log.Info("🔑 [Phase 10] Creating AppRole for EOS")

	// 1️⃣ Create or refresh AppRole credentials
	opts := DefaultAppRoleOptions()
	roleID, secretID, err := EnsureAppRole(client, log, opts)
	if err != nil {
		log.Error("❌ Failed to ensure AppRole", zap.Error(err))
		return "", "", fmt.Errorf("ensure AppRole: %w", err)
	}

	// 2️⃣ Write agent password (if provided) *before* systemd operations
	if password != "" {
		log.Info("🔏 Writing Vault Agent authentication secret",
			zap.String("path", shared.VaultAgentPassPath))

		if err := writeAgentPassword(password, log); err != nil {
			log.Error("❌ Failed to write Vault Agent password", zap.Error(err))
			return "", "", fmt.Errorf("write agent password: %w", err)
		}
		log.Info("✅ Vault Agent password written",
			zap.String("path", shared.VaultAgentPassPath))
	} else {
		log.Info("ℹ️ No agent password provided — skipping password file write")
	}

	// 3️⃣ Write Vault Agent systemd unit file
	if err := WriteAgentSystemdUnit(log); err != nil {
		log.Error("❌ Failed to write Vault Agent systemd unit", zap.Error(err))
		return "", "", fmt.Errorf("write agent systemd unit: %w", err)
	}
	log.Info("✅ Vault Agent systemd unit written")

	// 4️⃣ Reload systemd daemon and enable agent service
	if err := EnsureAgentServiceReady(log); err != nil {
		log.Error("❌ Failed to reload daemon and enable agent service", zap.Error(err))
		return "", "", fmt.Errorf("enable agent service: %w", err)
	}
	log.Info("✅ Vault Agent service ready and enabled")

	// 5️⃣ Done
	log.Info("✅ AppRole provisioning complete 🎉")
	return roleID, secretID, nil
}

func EnsureVaultAgentUnitExists(log *zap.Logger) error {
	if _, err := os.Stat(shared.VaultAgentServicePath); os.IsNotExist(err) {
		log.Warn("⚙️ Vault Agent systemd unit missing — creating", zap.String("path", shared.VaultAgentServicePath))
		if err := WriteAgentSystemdUnit(log); err != nil {
			log.Error("❌ Failed to write Vault Agent systemd unit", zap.Error(err))
			return fmt.Errorf("write Vault Agent unit: %w", err)
		}
		log.Info("✅ Vault Agent systemd unit ensured", zap.String("path", shared.VaultAgentServicePath))
	}
	return nil
}

// WriteAppRoleFiles writes the Vault AppRole role_id and secret_id to disk with secure permissions.
func WriteAppRoleFiles(roleID, secretID string, log *zap.Logger) error {
	dir := filepath.Dir(shared.RoleIDPath)
	log.Info("📁 Ensuring AppRole directory", zap.String("path", dir))
	if err := system.EnsureOwnedDir(dir, 0o700, shared.EosUser); err != nil {
		return err
	}

	pairs := map[string]string{
		shared.RoleIDPath:   roleID + "\n",
		shared.SecretIDPath: secretID + "\n",
	}
	for path, data := range pairs {
		log.Debug("✏️  Writing AppRole file", zap.String("path", path))
		if err := system.WriteOwnedFile(path, []byte(data), 0o600, shared.EosUser); err != nil {
			return err
		}
	}

	log.Info("✅ AppRole credentials written",
		zap.String("role_file", shared.RoleIDPath),
		zap.String("secret_file", shared.SecretIDPath))
	return nil
}

// refreshAppRoleCreds retrieves fresh credentials but does NOT write files.
func refreshAppRoleCreds(client *api.Client, log *zap.Logger) (string, string, error) {
	log.Debug("🔑 Requesting fresh AppRole credentials")

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

func RevokeRootToken(client *api.Client, token string, log *zap.Logger) error {
	client.SetToken(token)

	err := client.Auth().Token().RevokeSelf("")
	if err != nil {
		return fmt.Errorf("failed to revoke root token: %w", err)
	}

	log.Info("✅ Root token revoked")
	return nil
}

func writeAgentPassword(password string, log *zap.Logger) error {
	log.Debug("🔏 Writing Vault Agent password to file", zap.String("path", shared.VaultAgentPassPath))

	data := []byte(password + "\n")
	if err := os.WriteFile(shared.VaultAgentPassPath, data, 0600); err != nil {
		log.Error("❌ Failed to write password file", zap.String("path", shared.VaultAgentPassPath), zap.Error(err))
		return fmt.Errorf("failed to write Vault Agent password to %s: %w", shared.VaultAgentPassPath, err)
	}

	log.Info("✅ Vault Agent password file written",
		zap.String("path", shared.VaultAgentPassPath),
		zap.Int("bytes_written", len(data)))

	return nil
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

// EnsureAppRole provisions the AppRole if missing or refreshes credentials if needed.
func EnsureAppRole(client *api.Client, log *zap.Logger, opts shared.AppRoleOptions) (string, string, error) {
	if !opts.ForceRecreate {
		if _, err := os.Stat(shared.RoleIDPath); err == nil {
			log.Info("🔐 AppRole credentials already exist", zap.String("path", shared.RoleIDPath))
			if opts.RefreshCreds {
				return refreshAppRoleCreds(client, log)
			}
			return readAppRoleCredsFromDisk(log)
		}
	}

	log.Info("🛠 Creating Vault AppRole", zap.String("role", shared.RoleName))

	if err := EnableAppRoleAuth(client, log); err != nil {
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
	log.Info("✅ AppRole written")

	roleID, secretID, err := refreshAppRoleCreds(client, log)
	if err != nil {
		return "", "", fmt.Errorf("fetch AppRole creds: %w", err)
	}

	if err := WriteAppRoleFiles(roleID, secretID, log); err != nil {
		return "", "", fmt.Errorf("write AppRole files: %w", err)
	}

	return roleID, secretID, nil
}

func EnableAppRoleAuth(client *api.Client, log *zap.Logger) error {
	log.Info("📡 Enabling AppRole auth method if needed...")

	err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{Type: "approle"})
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "path is already in use") {
		log.Warn("⚠️ AppRole auth method may already be enabled", zap.Error(err))
		return nil
	}
	log.Error("❌ Failed to enable AppRole auth method", zap.Error(err))
	return fmt.Errorf("enable approle auth: %w", err)
}

func EnsureAgentServiceReady(log *zap.Logger) error {
	if err := EnsureVaultAgentUnitExists(log); err != nil {
		return err
	}
	log.Info("🚀 Reloading daemon and enabling Vault Agent service")
	if err := system.ReloadDaemonAndEnable(log, shared.VaultAgentService); err != nil {
		log.Error("❌ Failed to enable/start Vault Agent service", zap.Error(err))
		return fmt.Errorf("enable/start Vault Agent service: %w", err)
	}
	return nil
}
