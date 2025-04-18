/* pkg/vault/types.go */

package vault

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

var (
	// Vault Secrets + Tokens
	SecretsDir                = "/var/lib/eos/secrets"
	VaultInitPath             = filepath.Join(SecretsDir, "vault_init.json")
	VaultUserPath             = filepath.Join(SecretsDir, "vault_userpass.json")
	AppRoleIDPath             = filepath.Join(SecretsDir, "vault_role_id")
	AppSecretIDPath           = filepath.Join(SecretsDir, "vault_secret_id")
	VaultAgentTokenPath       = "/run/eos/vault-agent-eos.token"
	DelphiFallbackSecretsPath = filepath.Join(SecretsDir, "delphi_fallback.json")
	EosUserFallbackFile       = filepath.Join(SecretsDir, "vault_userpass.json")
	vaultClient               *api.Client
)

const (
	// Vault Agent & Policy Paths
	VaultAgentConfigPath = "/etc/vault-agent-eos.hcl"
	VaultAgentPassPath   = "/etc/vault-agent-eos.pass"
	VaultAgentUnitPath   = "/etc/systemd/system/vault-agent-eos.service"
	EosVaultPolicy       = "eos-policy"

	// AppRole-specific
	roleName = "eos-approle"
	rolePath = "auth/approle/role/" + roleName

	// Audit
	auditPath = "file/"
	mountPath = "sys/audit/" + auditPath
)

type CheckReport struct {
	Installed   bool
	Initialized bool
	Sealed      bool
	TokenReady  bool
	KVWorking   bool
	Notes       []string
}

type UserpassCreds struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UserSecret holds login and SSH key material for a system user.
type UserSecret struct {
	Username string `json:"username"`
	Password string `json:"password"`
	SSHKey   string `json:"ssh_private_key,omitempty"`
}

type AppRoleOptions struct {
	RoleName      string
	Policies      []string
	TokenTTL      string
	TokenMaxTTL   string
	SecretIDTTL   string
	ForceRecreate bool
	RefreshCreds  bool
}

func DefaultAppRoleOptions() AppRoleOptions {
	return AppRoleOptions{
		RoleName:      "eos",
		Policies:      []string{"eos-admin"},
		TokenTTL:      "1h",
		TokenMaxTTL:   "4h",
		SecretIDTTL:   "24h",
		ForceRecreate: false,
		RefreshCreds:  false,
	}
}

// VaultPath returns the full KV v2 path for data reads/writes.
func vaultPath(name string, log *zap.Logger) string {
	if strings.Contains(name, "/") {
		log.Warn("vaultPath should not receive slashes", zap.String("input", name))
	}
	final := fmt.Sprintf("eos/%s", name)
	log.Debug("Resolved Vault path", zap.String("input", name), zap.String("result", final))
	return final
}

// DiskPath constructs a fallback config path like: ~/.config/eos/<name>/config.json
func DiskPath(name string, log *zap.Logger) string {
	var final string
	if name == "vault_init" {
		final = filepath.Join(SecretsDir, "vault_init.json")
	} else {
		final = xdg.XDGConfigPath("eos", filepath.Join(name, "config.json"))
	}
	log.Debug("Resolved disk path", zap.String("input", name), zap.String("result", final))
	return final
}
