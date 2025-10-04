// pkg/xdg/credentials.go
package xdg

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// CredentialStore defines the interface for credential storage
type CredentialStore interface {
	SaveCredential(ctx context.Context, app, username, password string) (string, error)
	ReadCredential(ctx context.Context, app, username string) (string, error)
	DeleteCredential(ctx context.Context, app, username string) error
	ListCredentials(ctx context.Context, app string) ([]string, error)
}

// SECURITY: Protect global credential store with mutex to prevent race conditions
// Without this, concurrent SetCredentialStore() + SaveCredential() can cause:
// - Nil pointer dereference (panic)
// - Credential saved to wrong store
// - Data corruption
var (
	globalCredentialStore CredentialStore
	storeMutex            sync.RWMutex
)

// SetCredentialStore sets the global credential store implementation
func SetCredentialStore(store CredentialStore) {
	storeMutex.Lock()
	defer storeMutex.Unlock()
	globalCredentialStore = store
}

// SaveCredential saves a credential using the configured store (fail-closed)
func SaveCredential(app, username, password string) (string, error) {
	// Validate inputs first (before acquiring lock)
	if err := validateCredentialInputs(app, username, password); err != nil {
		return "", err
	}

	// Acquire read lock to check store
	storeMutex.RLock()
	store := globalCredentialStore
	storeMutex.RUnlock()

	// Fail closed - if store is not initialized, refuse to save
	if store == nil {
		return "", fmt.Errorf("credential store not initialized - refusing to save credentials insecurely")
	}

	// SECURITY: Add timeout to prevent indefinite hangs if Vault is down
	// Without this, hung goroutines accumulate → resource exhaustion
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return store.SaveCredential(ctx, app, username, password)
}

// ReadCredential reads a credential from the configured store
func ReadCredential(app, username string) (string, error) {
	if app == "" || username == "" {
		return "", fmt.Errorf("app and username are required")
	}

	storeMutex.RLock()
	store := globalCredentialStore
	storeMutex.RUnlock()

	if store == nil {
		return "", fmt.Errorf("credential store not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return store.ReadCredential(ctx, app, username)
}

// DeleteCredential deletes a credential from the configured store
func DeleteCredential(app, username string) error {
	if app == "" || username == "" {
		return fmt.Errorf("app and username are required")
	}

	storeMutex.RLock()
	store := globalCredentialStore
	storeMutex.RUnlock()

	if store == nil {
		return fmt.Errorf("credential store not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return store.DeleteCredential(ctx, app, username)
}

// ListCredentials lists all credentials for an app
func ListCredentials(app string) ([]string, error) {
	if app == "" {
		return nil, fmt.Errorf("app is required")
	}

	storeMutex.RLock()
	store := globalCredentialStore
	storeMutex.RUnlock()

	if store == nil {
		return nil, fmt.Errorf("credential store not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return store.ListCredentials(ctx, app)
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