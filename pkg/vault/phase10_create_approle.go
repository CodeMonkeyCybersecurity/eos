// pkg/vault/phase10_create_approle.go

package vault

import (
	"fmt"
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

// PHASE 10 — PhaseCreateAppRole()
//            └── EnsureAppRole()
//            └── WriteAppRoleFiles()
//            └── refreshAppRoleCreds()

// PhaseCreateAppRole creates the EOS AppRole and saves credentials.
func PhaseCreateAppRole(client *api.Client, log *zap.Logger) error {
	log.Info("🔑 [Phase 10] Creating AppRole for EOS")

	opts := DefaultAppRoleOptions()

	roleID, secretID, err := EnsureAppRole(client, log, opts)
	if err != nil {
		return fmt.Errorf("ensure AppRole: %w", err)
	}

	if err := WriteAppRoleFiles(roleID, secretID, log); err != nil {
		return fmt.Errorf("write AppRole files: %w", err)
	}

	log.Info("✅ AppRole credentials created and saved")
	return nil
}

// Enables the AppRole auth method and provisions the eos‑role.
func EnsureAppRoleAuth(client *api.Client, log *zap.Logger) error {
	// 1) Enable the approle auth method if not already
	log.Info("➕ Enabling AppRole auth method")
	if err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{Type: "approle"}); err != nil {
		if !strings.Contains(err.Error(), "path is already in use") {
			return fmt.Errorf("failed to enable approle auth: %w", err)
		}
	}
	log.Info("✅ AppRole auth method is enabled")

	// 2) Create the role
	log.Info("🛠 Provisioning AppRole", zap.String("role", shared.RoleName))
	_, err := client.Logical().Write(shared.RolePath, map[string]interface{}{
		"policies":      []string{shared.EosVaultPolicy},
		"token_ttl":     "4h",
		"token_max_ttl": "24h",
		"secret_id_ttl": "24h",
	})
	if err != nil {
		return fmt.Errorf("failed to create AppRole %s: %w", shared.RoleName, err)
	}
	log.Info("✅ AppRole provisioned", zap.String("role", shared.RoleName))
	return nil
}

// WriteAppRoleFiles writes the role_id & secret_id into /etc/vault and
// ensures the directory is 0700, owned by eos:eos.
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

func refreshAppRoleCreds(client *api.Client, log *zap.Logger) (string, string, error) {
	log.Debug("🔑 Requesting AppRole credentials from Vault...")

	// Read role_id from Vault
	roleID, err := client.Logical().Read(shared.RolePath + "/role-id")
	if err != nil {
		log.Error("❌ Failed to read AppRole role_id",
			zap.String("path", shared.RolePath+"/role-id"),
			zap.Error(err),
		)
		return "", "", err
	}

	// Generate secret_id
	secretID, err := client.Logical().Write(shared.RolePath+"/secret-id", nil)
	if err != nil {
		log.Error("❌ Failed to generate AppRole secret_id",
			zap.String("path", shared.RolePath+"/secret-id"),
			zap.Error(err),
		)
		return "", "", err
	}

	// Safely extract role_id
	rawRoleID, ok := roleID.Data["role_id"].(string)
	if !ok || rawRoleID == "" {
		log.Error("❌ Invalid or missing role_id in Vault response",
			zap.Any("data", roleID.Data),
		)
		return "", "", fmt.Errorf("invalid role_id in Vault response")
	}

	// Safely extract secret_id
	rawSecretID, ok := secretID.Data["secret_id"].(string)
	if !ok || rawSecretID == "" {
		log.Error("❌ Invalid or missing secret_id in Vault response",
			zap.Any("data", secretID.Data),
		)
		return "", "", fmt.Errorf("invalid secret_id in Vault response")
	}

	// Ensure directory exists (logged elsewhere if needed)
	log.Debug("💾 Writing AppRole credentials to disk")

	// Write role_id
	if err := system.WriteOwnedFile(shared.RoleIDPath, []byte(rawRoleID+"\n"), 0o640, shared.EosUser); err != nil {
		log.Error("❌ Failed to write role_id",
			zap.String("path", shared.RoleIDPath),
			zap.Error(err),
		)
		return "", "", err
	}

	// Write secret_id
	if err := system.WriteOwnedFile(shared.SecretIDPath, []byte(rawSecretID+"\n"), 0o640, shared.EosUser); err != nil {
		log.Error("❌ Failed to write secret_id",
			zap.String("path", shared.SecretIDPath),
			zap.Error(err),
		)
		return "", "", err
	}

	log.Info("✅ AppRole credentials written to disk",
		zap.String("role_id_path", shared.RoleIDPath),
		zap.String("secret_id_path", shared.SecretIDPath),
	)
	return rawRoleID, rawSecretID, nil
}



func RevokeRootToken(client *api.Client, token string, log *zap.Logger) error {
	client.SetToken(token)

	err := client.Auth().Token().RevokeSelf("")
	if err != nil {
		return fmt.Errorf("failed to revoke root token: %w", err)
	}

	fmt.Println("✅ Root token revoked.")
	return nil
}
