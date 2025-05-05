package shared

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// AppRole constants and paths
const (
	AppRoleName      = "eos-approle"
	AppRolePath      = "auth/approle/role/" + AppRoleName
	AppRoleLoginPath = "auth/approle/login"

	AppRoleRoleIDPath   = AppRolePath + "/role-id"
	AppRoleSecretIDPath = AppRolePath + "/secret-id"
)

// AppRoleOptions defines configuration for provisioning or refreshing a Vault AppRole.
type AppRoleOptions struct {
	RoleName      string   `json:"role_name,omitempty"`
	Policies      []string `json:"policies,omitempty"`
	TokenTTL      string   `json:"token_ttl,omitempty"`
	TokenMaxTTL   string   `json:"token_max_ttl,omitempty"`
	SecretIDTTL   string   `json:"secret_id_ttl,omitempty"`
	ForceRecreate bool     `json:"force_recreate,omitempty"`
	RefreshCreds  bool     `json:"refresh_creds,omitempty"`
}

// AppRolePathsStruct holds credential file paths.
type AppRolePathsStruct struct {
	RoleID   string
	SecretID string
}

var AppRolePaths = AppRolePathsStruct{
	RoleID:   filepath.Join(SecretsDir, "role_id"),
	SecretID: filepath.Join(SecretsDir, "secret_id"),
}

// WriteAppRoleFile writes a single secret to a file.
func WriteAppRoleFile(path, value string, perm os.FileMode) error {
	if err := os.WriteFile(path, []byte(value), perm); err != nil {
		zap.L().Error("❌ Failed to write secret file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("write %s: %w", path, err)
	}
	zap.L().Info("✅ Secret file written", zap.String("path", path), zap.String("perm", fmt.Sprintf("%#o", perm)))
	return nil
}

// WriteAppRoleFiles writes multiple secrets to files.
func WriteAppRoleFiles(pairs map[string]string, perm os.FileMode) error {
	for path, value := range pairs {
		if err := WriteAppRoleFile(path, value, perm); err != nil {
			return err
		}
	}
	return nil
}

// BuildAppRoleLoginPayload creates the payload for AppRole login.
func BuildAppRoleLoginPayload(roleID, secretID string) map[string]interface{} {
	return map[string]interface{}{
		"role_id":   strings.TrimSpace(roleID),
		"secret_id": strings.TrimSpace(secretID),
	}
}

// DefaultAppRoleData is the default Vault AppRole configuration.
var DefaultAppRoleData = map[string]interface{}{
	"policies":      []string{EosVaultPolicy},
	"token_ttl":     VaultDefaultTokenTTL,
	"token_max_ttl": VaultDefaultTokenMaxTTL,
	"secret_id_ttl": VaultDefaultSecretIDTTL,
}

// DefaultAppRoleOptions returns the default settings used when creating the eos-approle in Vault.
func DefaultAppRoleOptions() AppRoleOptions {
	return AppRoleOptions{
		RoleName:      EosID,
		Policies:      []string{EosVaultPolicy},
		TokenTTL:      "1h",
		TokenMaxTTL:   "4h",
		SecretIDTTL:   "24h",
		ForceRecreate: false,
		RefreshCreds:  false,
	}
}
