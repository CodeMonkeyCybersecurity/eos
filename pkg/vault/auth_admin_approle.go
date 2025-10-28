// pkg/vault/auth_admin_approle.go
// Admin AppRole authentication and credential management
//
// This file implements HashiCorp best practice of using admin-level AppRole
// instead of root token for operational commands.
//
// Admin AppRole has elevated privileges (eos-admin-policy) for:
// - Policy updates
// - MFA enforcement repair
// - Configuration drift correction
// - Secret engine management
//
// Unlike root token:
// - Still policy-bound (not unlimited access)
// - All operations audited
// - Credentials can be rotated
// - Follows production security patterns

package vault

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// readAdminAppRoleCredsFromDisk reads admin AppRole credentials from disk
// Returns: roleID, secretID, error
func readAdminAppRoleCredsFromDisk(rc *eos_io.RuntimeContext) (string, string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Debug("Reading admin AppRole credentials from disk",
		zap.String("role_id_path", shared.AdminAppRolePaths.RoleID),
		zap.String("secret_id_path", shared.AdminAppRolePaths.SecretID))

	// Read role_id
	roleIDBytes, err := os.ReadFile(shared.AdminAppRolePaths.RoleID)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debug("Admin AppRole role_id file not found (admin AppRole not configured)",
				zap.String("path", shared.AdminAppRolePaths.RoleID))
			return "", "", cerr.Wrap(err, "admin AppRole not configured")
		}
		log.Error("Failed to read admin AppRole role_id from disk",
			zap.String("path", shared.AdminAppRolePaths.RoleID),
			zap.Error(err))
		return "", "", cerr.Wrap(err, "read admin role_id from disk")
	}
	roleID := strings.TrimSpace(string(roleIDBytes))

	// Validate role_id
	if roleID == "" {
		log.Error("Admin AppRole role_id file is empty",
			zap.String("path", shared.AdminAppRolePaths.RoleID))
		return "", "", cerr.New("admin role_id file is empty")
	}

	if len(roleID) < 36 { // UUIDs are at least 36 chars
		log.Error("Admin AppRole role_id appears invalid (too short)",
			zap.String("path", shared.AdminAppRolePaths.RoleID),
			zap.Int("length", len(roleID)),
			zap.Int("min_expected", 36))
		return "", "", cerr.Newf("admin role_id appears invalid: length %d < 36", len(roleID))
	}

	log.Debug("Admin AppRole role_id read and validated successfully",
		zap.Int("length", len(roleID)))

	// Read secret_id
	secretIDBytes, err := os.ReadFile(shared.AdminAppRolePaths.SecretID)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debug("Admin AppRole secret_id file not found",
				zap.String("path", shared.AdminAppRolePaths.SecretID))
			return "", "", cerr.Wrap(err, "admin AppRole secret_id not found")
		}
		log.Error("Failed to read admin AppRole secret_id from disk",
			zap.String("path", shared.AdminAppRolePaths.SecretID),
			zap.Error(err))
		return "", "", cerr.Wrap(err, "read admin secret_id from disk")
	}
	secretID := strings.TrimSpace(string(secretIDBytes))

	// Validate secret_id
	if secretID == "" {
		log.Error("Admin AppRole secret_id file is empty",
			zap.String("path", shared.AdminAppRolePaths.SecretID))
		return "", "", cerr.New("admin secret_id file is empty")
	}

	if len(secretID) < 36 { // UUIDs are at least 36 chars
		log.Error("Admin AppRole secret_id appears invalid (too short)",
			zap.String("path", shared.AdminAppRolePaths.SecretID),
			zap.Int("length", len(secretID)),
			zap.Int("min_expected", 36))
		return "", "", cerr.Newf("admin secret_id appears invalid: length %d < 36", len(secretID))
	}

	log.Debug("Admin AppRole secret_id read and validated successfully",
		zap.Int("length", len(secretID)))

	return roleID, secretID, nil
}

// tryAdminAppRole attempts authentication using admin AppRole credentials
// This is the preferred method for operational commands (NOT initial setup)
func tryAdminAppRole(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Debug("Attempting admin AppRole authentication")

	// Read credentials from disk
	roleID, secretID, err := readAdminAppRoleCredsFromDisk(rc)
	if err != nil {
		log.Debug("Admin AppRole credentials not available",
			zap.Error(err))
		return "", cerr.Wrap(err, "admin AppRole credentials not available")
	}

	// Create AppRole auth
	auth, err := approle.NewAppRoleAuth(roleID, &approle.SecretID{
		FromString: secretID,
	}, approle.WithMountPath("auth/approle"))
	if err != nil {
		log.Error("Failed to create admin AppRole auth",
			zap.Error(err))
		return "", cerr.Wrap(err, "create admin AppRole auth")
	}

	// Perform login
	log.Debug("Performing admin AppRole login")
	secret, err := client.Auth().Login(context.Background(), auth)
	if err != nil {
		log.Error("Admin AppRole login failed",
			zap.Error(err))
		return "", cerr.Wrap(err, "admin AppRole login failed")
	}

	if secret == nil || secret.Auth == nil {
		log.Error("No auth info returned from admin AppRole login")
		return "", cerr.New("no auth info returned from admin AppRole login")
	}

	log.Info("Admin AppRole authentication successful",
		zap.String("token_accessor", secret.Auth.Accessor),
		zap.Any("policies", secret.Auth.Policies))

	return secret.Auth.ClientToken, nil
}

// WriteAdminAppRoleFiles writes admin AppRole credentials to disk
// This is called during admin AppRole creation (Phase 10b2)
func WriteAdminAppRoleFiles(rc *eos_io.RuntimeContext, roleID, secretID string) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Writing admin AppRole credentials to disk",
		zap.String("role_id_path", shared.AdminAppRolePaths.RoleID),
		zap.String("secret_id_path", shared.AdminAppRolePaths.SecretID))

	// Ensure secrets directory exists
	secretsDir := shared.SecretsDir
	if err := os.MkdirAll(secretsDir, shared.RuntimeDirPerms); err != nil {
		log.Error("Failed to ensure secrets directory exists",
			zap.String("dir", secretsDir),
			zap.Error(err))
		return cerr.Wrap(err, "ensure secrets directory")
	}

	// SECURITY FIX (Phase 2): Use SecureWriteCredentialOrOverwrite to prevent TOCTOU
	// Admin credentials are even more sensitive than agent credentials
	log.Info("Writing admin role_id file (secure FD-based)",
		zap.String("path", shared.AdminAppRolePaths.RoleID))
	if err := SecureWriteCredentialOrOverwrite(rc, shared.AdminAppRolePaths.RoleID, roleID, shared.FilePermOwnerReadWrite, "admin_role_id"); err != nil {
		log.Error("Failed to securely write admin role_id file",
			zap.String("path", shared.AdminAppRolePaths.RoleID),
			zap.Error(err))
		return cerr.Wrap(err, "securely write admin role_id file")
	}
	log.Info("Admin role_id file written and verified",
		zap.String("path", shared.AdminAppRolePaths.RoleID),
		zap.String("perm", fmt.Sprintf("%#o", shared.FilePermOwnerReadWrite)))

	// Write secret_id file
	log.Info("Writing admin secret_id file (secure FD-based)",
		zap.String("path", shared.AdminAppRolePaths.SecretID))
	if err := SecureWriteCredentialOrOverwrite(rc, shared.AdminAppRolePaths.SecretID, secretID, shared.FilePermOwnerReadWrite, "admin_secret_id"); err != nil {
		log.Error("Failed to securely write admin secret_id file",
			zap.String("path", shared.AdminAppRolePaths.SecretID),
			zap.Error(err))
		return cerr.Wrap(err, "securely write admin secret_id file")
	}
	log.Info("Admin secret_id file written and verified",
		zap.String("path", shared.AdminAppRolePaths.SecretID),
		zap.String("perm", fmt.Sprintf("%#o", shared.FilePermOwnerReadWrite)))

	log.Info("Admin AppRole credentials written successfully")
	return nil
}

// EnsureAdminAppRole creates or updates the admin AppRole in Vault
// Returns: roleID, secretID, error
func EnsureAdminAppRole(rc *eos_io.RuntimeContext, client *api.Client) (string, string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Ensuring admin AppRole exists in Vault",
		zap.String("role_name", shared.AdminAppRoleName))

	// Create admin AppRole configuration
	// Admin AppRole has elevated privileges but is still policy-bound
	adminRoleData := map[string]interface{}{
		"policies":      []string{shared.EosDefaultPolicyName, shared.EosAdminPolicyName},
		"token_ttl":     shared.VaultDefaultTokenTTL,    // 4h
		"token_period":  shared.VaultDefaultTokenTTL,    // 4h - infinitely renewable
		"secret_id_ttl": shared.VaultDefaultSecretIDTTL, // 24h
	}

	// Write admin AppRole to Vault
	rolePath := shared.AdminAppRolePath
	log.Debug("Writing admin AppRole configuration to Vault",
		zap.String("path", rolePath),
		zap.Any("config", adminRoleData))

	_, err := client.Logical().Write(rolePath, adminRoleData)
	if err != nil {
		log.Error("Failed to write admin AppRole configuration",
			zap.String("path", rolePath),
			zap.Error(err))
		return "", "", cerr.Wrap(err, "write admin AppRole configuration")
	}

	log.Info("Admin AppRole configuration written to Vault")

	// Read role_id
	roleIDPath := shared.AdminAppRoleRoleIDPath
	log.Debug("Reading admin AppRole role_id from Vault",
		zap.String("path", roleIDPath))

	roleIDResp, err := client.Logical().Read(roleIDPath)
	if err != nil {
		log.Error("Failed to read admin AppRole role_id",
			zap.String("path", roleIDPath),
			zap.Error(err))
		return "", "", cerr.Wrap(err, "read admin role_id")
	}

	if roleIDResp == nil || roleIDResp.Data == nil {
		log.Error("Admin AppRole role_id response is nil")
		return "", "", cerr.New("admin role_id response is nil")
	}

	roleID, ok := roleIDResp.Data["role_id"].(string)
	if !ok || roleID == "" {
		log.Error("Admin AppRole role_id is empty or invalid",
			zap.Any("data", roleIDResp.Data))
		return "", "", cerr.New("admin role_id is empty or invalid")
	}

	log.Debug("Admin AppRole role_id retrieved",
		zap.String("role_id", roleID))

	// Generate secret_id
	secretIDPath := shared.AdminAppRoleSecretIDPath
	log.Debug("Generating admin AppRole secret_id",
		zap.String("path", secretIDPath))

	secretIDResp, err := client.Logical().Write(secretIDPath, nil)
	if err != nil {
		log.Error("Failed to generate admin AppRole secret_id",
			zap.String("path", secretIDPath),
			zap.Error(err))
		return "", "", cerr.Wrap(err, "generate admin secret_id")
	}

	if secretIDResp == nil || secretIDResp.Data == nil {
		log.Error("Admin AppRole secret_id response is nil")
		return "", "", cerr.New("admin secret_id response is nil")
	}

	secretID, ok := secretIDResp.Data["secret_id"].(string)
	if !ok || secretID == "" {
		log.Error("Admin AppRole secret_id is empty or invalid",
			zap.Any("data", secretIDResp.Data))
		return "", "", cerr.New("admin secret_id is empty or invalid")
	}

	log.Debug("Admin AppRole secret_id generated",
		zap.Int("secret_id_length", len(secretID)))

	log.Info("Admin AppRole credentials obtained successfully",
		zap.String("role_name", shared.AdminAppRoleName),
		zap.String("role_id", roleID))

	return roleID, secretID, nil
}
