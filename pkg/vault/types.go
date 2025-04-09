/* pkg/vault/reader.go */

package vault

import (
	"fmt"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
)

const fallbackSecretsPath = "/var/lib/eos/secrets/delphi-fallback.yaml"

// vaultPath constructs the Vault KV path like: secret/eos/<name>/config
func vaultPath(name string) string {
	return fmt.Sprintf("secret/eos/%s/config", name)
}

// diskPath constructs a fallback config path like: ~/.config/eos/<name>/config.json
func diskPath(name string) string {
	return xdg.XDGConfigPath("eos", filepath.Join(name, "config.json"))
}

// initResult is the JSON structure returned by "vault operator init -format=json".
type InitResult struct {
	UnsealKeysB64 []string `json:"unseal_keys_b64"`
	RootToken     string   `json:"root_token"`
}

type UserpassCreds struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}
