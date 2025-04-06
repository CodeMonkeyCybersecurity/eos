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

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH key from %s: %w", keyPath, err)
	}
	secret.SSHKey = string(keyData)

	vaultPath := fmt.Sprintf("secret/users/%s", username)
	return WriteStruct(vaultPath, &secret)
}

func WriteUserSecret(username string, data any) error {
	return WriteVaultJSON(fmt.Sprintf("secret/users/%s", username), data)
}

func LoadUserSecret(username string) (*UserSecret, error) {
	var secret UserSecret
	err := ReadVaultJSON(fmt.Sprintf("secret/users/%s", username), &secret)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

func (s *UserSecret) IsValid() bool {
	return s.Username != "" && s.Password != ""
}
