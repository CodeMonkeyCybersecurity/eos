package vault

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// StoreUserSecret reads an SSH key and stores full user credentials in Vault.
func StoreUserSecret(username, password, keyPath string, log *zap.Logger) error {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH key from %s: %w", keyPath, err)
	}
	secret := UserSecret{Username: username, Password: password, SSHKey: string(keyData)}
	return WriteToVaultAt("secret", fmt.Sprintf("users/%s", username), &secret)
}

// LoadUserSecret retrieves and validates a user's secret from Vault.
func LoadUserSecret(client *api.Client, username string, log *zap.Logger) (*UserSecret, error) {
	var secret UserSecret
	if err := ReadFromVaultAt(context.Background(), "secret", userVaultPath(username, log), &secret, log); err != nil {
		return nil, err
	}
	if !secret.IsValid() {
		return nil, fmt.Errorf("incomplete secret for user %s", username)
	}
	return &secret, nil
}

// IsValid ensures required fields are populated.
// IsValid ensures required fields are populated.
func (s *UserSecret) IsValid() bool {
	return s.Username != "" && s.Password != ""
}

// userVaultPath returns the Vault path for a given user.
func userVaultPath(username string, log *zap.Logger) string {
	path := fmt.Sprintf("secret/users/%s", username)
	log.Debug("Resolved Vault path for user", zap.String("username", username), zap.String("path", path))
	return path
}
