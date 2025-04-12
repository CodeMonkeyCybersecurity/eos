/* pkg/vault/types.go */

package vault

import (
	"fmt"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"github.com/hashicorp/vault/api"
)

const (
	diskSecretsPath           = "/var/lib/eos/secrets"
	delphiFallbackSecretsPath = diskSecretsPath + "delphi-fallback.json"
	auditPath                 = "file/"
	mountPath                 = "sys/audit/" + auditPath
	EosVaultPolicy            = "eos-policy"
	EosUserFallbackFile       = diskSecretsPath + "vault-userpass.json"
)

// vaultPath returns the full KV v2 path for data reads/writes.
func vaultPath(name string) string {
	return fmt.Sprintf("secret/data/eos/%s", name)
}

// diskPath constructs a fallback config path like: ~/.config/eos/<name>/config.json
func diskPath(name string) string {
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
