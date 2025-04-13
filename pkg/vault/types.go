/* pkg/vault/types.go */

package vault

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"github.com/hashicorp/vault/api"
)

const (
	diskSecretsPath      = "/var/lib/eos/secrets"
	auditPath            = "file/"
	mountPath            = "sys/audit/" + auditPath
	EosVaultPolicy       = "eos-policy"
	VaultAgentConfigPath = "/etc/vault-agent-eos.hcl"
	VaultTokenSinkPath   = "/etc/vault-agent-eos.token"
	RoleIDPath           = "/etc/vault/role_id"
	SecretIDPath         = "/etc/vault/secret_id"
)

var (
	DelphiFallbackSecretsPath = filepath.Join(diskSecretsPath, "delphi_fallback.json")
	EosUserFallbackFile       = filepath.Join(diskSecretsPath, "vault_userpass.json")
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
		return filepath.Join(diskSecretsPath, "vault_init.json")
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
