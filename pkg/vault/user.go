package vault

import (
	"fmt"
	"os"
)

// UserSecret holds login and SSH key material for a system user.
type UserSecret struct {
	Username string `json:"username"`
	Password string `json:"password"`
	SSHKey   string `json:"ssh_private_key,omitempty"`
}

// StoreUserSecret stores a user's credentials and SSH key in Vault.
func StoreUserSecret(username, password, keyPath string) error {
	secret := UserSecret{
		Username: username,
		Password: password,
	}

	if keyData, err := os.ReadFile(keyPath); err == nil {
		secret.SSHKey = string(keyData)
	}

	vaultPath := fmt.Sprintf("secret/users/%s", username)
	return WriteStruct(vaultPath, &secret)
}
