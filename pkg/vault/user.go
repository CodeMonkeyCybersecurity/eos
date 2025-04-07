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

// StoreUserSecret reads an SSH key and stores full user credentials in Vault.
func StoreUserSecret(username, password, keyPath string) error {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH key from %s: %w", keyPath, err)
	}
	secret := UserSecret{Username: username, Password: password, SSHKey: string(keyData)}
	return writeVaultJSON(userVaultPath(username), &secret)
}

// LoadUserSecret retrieves and validates a user's secret from Vault.
func LoadUserSecret(username string) (*UserSecret, error) {
	var secret UserSecret
	if err := readVaultJSON(userVaultPath(username), &secret); err != nil {
		return nil, err
	}
	if !secret.IsValid() {
		return nil, fmt.Errorf("incomplete secret for user %s", username)
	}
	return &secret, nil
}

// IsValid ensures required fields are populated.
func (s *UserSecret) IsValid() bool {
	return s.Username != "" && s.Password != ""
}

// userVaultPath returns the Vault path for a given user.
func userVaultPath(username string) string {
	return fmt.Sprintf("secret/users/%s", username)
}
