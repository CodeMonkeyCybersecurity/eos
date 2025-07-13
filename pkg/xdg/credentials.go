// pkg/xdg/credentials.go
package xdg

import (
	"context"
	"fmt"
	"strings"
)

// CredentialStore defines the interface for credential storage
type CredentialStore interface {
	SaveCredential(ctx context.Context, app, username, password string) (string, error)
	ReadCredential(ctx context.Context, app, username string) (string, error)
	DeleteCredential(ctx context.Context, app, username string) error
	ListCredentials(ctx context.Context, app string) ([]string, error)
}

// Global credential store instance (fail-closed by default)
var globalCredentialStore CredentialStore

// SetCredentialStore sets the global credential store implementation
func SetCredentialStore(store CredentialStore) {
	globalCredentialStore = store
}

// SaveCredential saves a credential using the configured store (fail-closed)
func SaveCredential(app, username, password string) (string, error) {
	// Fail closed - if store is not initialized, refuse to save
	if globalCredentialStore == nil {
		return "", fmt.Errorf("credential store not initialized - refusing to save credentials insecurely")
	}

	// Validate inputs
	if err := validateCredentialInputs(app, username, password); err != nil {
		return "", err
	}

	return globalCredentialStore.SaveCredential(context.Background(), app, username, password)
}

// ReadCredential reads a credential from the configured store
func ReadCredential(app, username string) (string, error) {
	if globalCredentialStore == nil {
		return "", fmt.Errorf("credential store not initialized")
	}

	if app == "" || username == "" {
		return "", fmt.Errorf("app and username are required")
	}

	return globalCredentialStore.ReadCredential(context.Background(), app, username)
}

// DeleteCredential deletes a credential from the configured store
func DeleteCredential(app, username string) error {
	if globalCredentialStore == nil {
		return fmt.Errorf("credential store not initialized")
	}

	if app == "" || username == "" {
		return fmt.Errorf("app and username are required")
	}

	return globalCredentialStore.DeleteCredential(context.Background(), app, username)
}

// ListCredentials lists all credentials for an app
func ListCredentials(app string) ([]string, error) {
	if globalCredentialStore == nil {
		return nil, fmt.Errorf("credential store not initialized")
	}

	if app == "" {
		return nil, fmt.Errorf("app is required")
	}

	return globalCredentialStore.ListCredentials(context.Background(), app)
}

// validateCredentialInputs validates inputs for credential operations
func validateCredentialInputs(app, username, password string) error {
	if app == "" {
		return fmt.Errorf("app name is required")
	}
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if password == "" {
		return fmt.Errorf("password is required")
	}
	
	// Check for path traversal attempts
	if strings.Contains(app, "..") || strings.Contains(username, "..") {
		return fmt.Errorf("path traversal detected")
	}
	
	// Check for null bytes
	if strings.Contains(app, "\x00") || strings.Contains(username, "\x00") || strings.Contains(password, "\x00") {
		return fmt.Errorf("null bytes not allowed")
	}
	
	// Check for other dangerous characters
	if strings.ContainsAny(app+username, "/\\") {
		return fmt.Errorf("invalid characters in app or username")
	}
	
	return nil
}

// SanitizePathComponent removes dangerous characters from path components
func SanitizePathComponent(component string) string {
	// Remove dangerous characters
	safe := strings.ReplaceAll(component, "..", "")
	safe = strings.ReplaceAll(safe, "/", "-")
	safe = strings.ReplaceAll(safe, "\\", "-")
	safe = strings.ReplaceAll(safe, "\x00", "")
	safe = strings.TrimSpace(safe)
	
	// Replace other problematic characters
	safe = strings.ReplaceAll(safe, " ", "-")
	safe = strings.ReplaceAll(safe, "@", "-at-")
	
	return safe
}