// pkg/shared/vault_userpass.go

package shared

import (
	"path/filepath"
)

var (
	// Path to fallback file storing userpass credentials
	EosUserPassFallback = filepath.Join(SecretsDir, "vault_userpass.json")

	// Fallback password file path (for eos user)
	EosUserPassPasswordFile = filepath.Join(EosUserPassFallback, "userpass-password")
)

// Userpass paths and constants
const (
	UserpassPathPrefix  = "auth/userpass/users/"
	EosUserpassPath     = UserpassPathPrefix + "eos"
	EosUserpassPolicy   = "eos-policy"
	VaultSecretMount    = "secret"
	UserpassKVPath      = VaultSecretMount + "/eos/userpass-password"
	FallbackPasswordKey = "eos-userpass-password"
)

func UserDataTemplate(password string) map[string]interface{} {
	return map[string]interface{}{
		"password": password,
		"policies": []string{EosUserpassPolicy},
	}
}

// FallbackSecretsTemplate provides the fallback secrets map for disk
func FallbackSecretsTemplate(password string) map[string]interface{} {
	return map[string]interface{}{
		FallbackPasswordKey: password,
	}
}
