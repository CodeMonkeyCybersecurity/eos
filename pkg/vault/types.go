/* pkg/vault/types.go */

package vault

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"github.com/hashicorp/vault/api"
)

var (
	// Vault Secrets + Tokens
	SecretsDir          = "/var/lib/eos/secrets"
	VaultInitPath       = filepath.Join(SecretsDir, "vault_init.json")
	VaultUserPath       = filepath.Join(SecretsDir, "vault_userpass.json")
	AppRoleIDPath       = filepath.Join(SecretsDir, "vault_role_id")
	AppSecretIDPath     = filepath.Join(SecretsDir, "vault_secret_id")
	VaultAgentTokenPath = "/run/eos/vault-agent-eos.token"
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

var (
	DelphiFallbackSecretsPath = filepath.Join(SecretsDir, "delphi_fallback.json")
	EosUserFallbackFile       = filepath.Join(SecretsDir, "vault_userpass.json")
)

// vaultPath returns the full KV v2 path for data reads/writes.
// vaultPath returns the full KV v2 path for data reads/writes.
func vaultPath(name string) string {
	if strings.Contains(name, "/") {
		fmt.Printf("⚠️  vaultPath should not receive slashes — got: %q\n", name)
	}
	return fmt.Sprintf("eos/%s", name)
}

// DiskPath constructs a fallback config path like: ~/.config/eos/<name>/config.json
func DiskPath(name string) string {
	if name == "vault_init" {
		return filepath.Join(SecretsDir, "vault_init.json")
	}
	return xdg.XDGConfigPath("eos", filepath.Join(name, "config.json"))
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

var vaultClient *api.Client
