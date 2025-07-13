// pkg/xdg/credentials.go
package xdg

import (
	"fmt"
	"os"
	"path/filepath"
)

// SaveCredentialToFile is the deprecated file-based credential storage
// DEPRECATED: Use SaveCredential which now uses Vault
func SaveCredentialToFile(app, username, password string) (string, error) {
	configDir := XDGConfigPath(app, "credentials")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", err
	}
	credFile := filepath.Join(configDir, fmt.Sprintf("%s.secret", username))
	err := os.WriteFile(credFile, []byte(password), 0600)
	return credFile, err
}
