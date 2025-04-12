/* pkg/vault/reader.go */

package vault

import (
	"fmt"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"github.com/hashicorp/vault/api"
)

const (
	fallbackSecretsPath = "/var/lib/eos/secrets/delphi-fallback.yaml"
	auditPath           = "file/"
	mountPath           = "sys/audit/" + auditPath
	EosVaultPolicy      = "eos-policy"
)

// vaultPath constructs the Vault KV path like: secret/eos/<name>/config
func vaultPath(name string) string {
	return fmt.Sprintf("secret/eos/%s/config", name)
}

// diskPath constructs a fallback config path like: ~/.config/eos/<name>/config.json
func diskPath(name string) string {
	return xdg.XDGConfigPath("eos", filepath.Join(name, "config.json"))
}

type UserpassCreds struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// UserSecret holds login and SSH key material for a system user.
type UserSecret struct {
	Username string `json:"username"`
	Password string `json:"password"`
	SSHKey   string `json:"ssh_private_key,omitempty"`
}

var vaultClient *api.Client
