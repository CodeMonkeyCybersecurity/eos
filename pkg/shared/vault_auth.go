// pkg/shared/vault_auth.go

package shared

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

//
// ---------------- TYPES ----------------
//

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

//
// ---------------- VARS ----------------
//

var AppRolePaths = AppRolePathsStruct{
	RoleID:   filepath.Join(SecretsDir, "role_id"),
	SecretID: filepath.Join(SecretsDir, "secret_id"),
}

// DefaultAppRoleData is the default Vault AppRole configuration.
//
// CRITICAL P0 FIX: Added token_period to enable automatic token renewal
// CRITICAL P0 FIX: Removed token_max_ttl to prevent conflict with token_period
//
// HashiCorp Vault Token Types:
// - Without token_period: tokens are renewable but have max_ttl limit (eventually expire)
// - With token_period: tokens are infinitely renewable (perfect for long-running services)
//
// Why token_period is CRITICAL for Vault Agent:
// 1. Vault Agent is a long-running daemon (systemd service)
// 2. Without token_period, tokens hit max_ttl and expire (4h default)
// 3. Agent can't re-authenticate automatically (needs human intervention)
// 4. With token_period, Agent auto-renews token before expiry FOREVER
//
// Why token_max_ttl is REMOVED:
// - HashiCorp docs: "When a period and an explicit max TTL were both set on a token,
//   it behaves as a periodic token. However, once the explicit max TTL is reached,
//   the token will be revoked."
// - Setting token_max_ttl with token_period defeats the purpose of periodic tokens
// - For periodic tokens, TTL is reset on each renewal (no max limit needed)
//
// Security Trade-off:
// - Risk: Compromised token could be renewed indefinitely
// - Mitigation: Token bound to specific AppRole policies, SecretID has TTL (24h)
// - Additional Mitigation: Token must be renewed every 4h (detectable activity)
// - Benefit: Zero-touch operation, no deployment failures from expired tokens
//
// References:
// - https://developer.hashicorp.com/vault/docs/concepts/tokens#token-time-to-live-periodic-tokens-and-explicit-max-ttls
// - https://developer.hashicorp.com/vault/docs/auth/approle#configuration
var DefaultAppRoleData = map[string]interface{}{
	"policies":     []string{EosDefaultPolicyName},
	"token_ttl":    VaultDefaultTokenTTL,    // 4h - Initial TTL after authentication
	"token_period": VaultDefaultTokenTTL,    // 4h - ENABLES INFINITE RENEWAL (resets TTL on each renewal)
	// token_max_ttl REMOVED - conflicts with token_period (would limit periodic tokens to max_ttl)
	"secret_id_ttl": VaultDefaultSecretIDTTL, // 24h - SecretID expires (requires new authentication)
}

//
// ---------------- FUNCTIONS ----------------
//

// WriteAppRoleFile writes a single secret to a file.
func WriteAppRoleFile(path, value string, perm os.FileMode) error {
	if err := os.WriteFile(path, []byte(value), perm); err != nil {
		zap.L().Error(" Failed to write secret file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("write %s: %w", path, err)
	}
	zap.L().Info(" Secret file written", zap.String("path", path), zap.String("perm", fmt.Sprintf("%#o", perm)))
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

// DefaultAppRoleOptions returns the default settings used when creating the eos-approle in Vault.
func DefaultAppRoleOptions() AppRoleOptions {
	return AppRoleOptions{
		RoleName:      AppRoleName, // fix: use AppRoleName ("eos-approle") instead of EosID ("eos")
		Policies:      []string{EosDefaultPolicyName, EosAdminPolicyName}, // Admin role per HashiCorp best practices
		TokenTTL:      "1h",
		TokenMaxTTL:   "4h",
		SecretIDTTL:   "24h",
		ForceRecreate: false,
		RefreshCreds:  false,
	}
}

var (
	// Path to fallback file storing userpass credentials
	EosUserPassFallback = filepath.Join(SecretsDir, "vault_userpass.json")

	// Fallback password file path (for eos user)
	EosUserPassPasswordFile = filepath.Join(EosUserPassFallback, "userpass-password")
)

func UserDataTemplate(password string) map[string]interface{} {
	return map[string]interface{}{
		"password": password,
		// Assign both default (self-management) and admin (infrastructure management) policies
		// This makes eos user an administrator (non-root) per HashiCorp best practices
		"policies": []string{EosDefaultPolicyName, EosAdminPolicyName},
	}
}

// FallbackSecretsTemplate provides the fallback secrets map for disk
func FallbackSecretsTemplate(password string) map[string]interface{} {
	return map[string]interface{}{
		FallbackPasswordKey: password,
	}
}
