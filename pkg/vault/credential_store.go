// pkg/vault/credential_store.go
package vault

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/text/unicode/norm"
)

// VaultCredentialStore provides secure credential storage using HashiCorp Vault
type VaultCredentialStore struct {
	client *api.Client
	prefix string // Vault path prefix for credentials
}

// NewVaultCredentialStore creates a new Vault-based credential store
// Returns nil if Vault is not available (fail-closed behavior)
func NewVaultCredentialStore(rc *eos_io.RuntimeContext, pathPrefix string) (*VaultCredentialStore, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Try to get Vault client
	client, err := GetVaultClient(rc)
	if err != nil {
		logger.Error("Failed to initialize Vault client for credential storage",
			zap.Error(err))
		return nil, fmt.Errorf("vault not available: %w", err)
	}

	// Verify Vault is accessible and unsealed
	health, err := client.Sys().Health()
	if err != nil {
		logger.Error("Vault health check failed",
			zap.Error(err))
		return nil, fmt.Errorf("vault health check failed: %w", err)
	}

	if health.Sealed {
		logger.Error("Vault is sealed")
		return nil, fmt.Errorf("vault is sealed")
	}

	if !health.Initialized {
		logger.Error("Vault is not initialized")
		return nil, fmt.Errorf("vault is not initialized")
	}

	logger.Info("Vault credential store initialized successfully",
		zap.String("path_prefix", pathPrefix),
		zap.Bool("standby", health.Standby))

	return &VaultCredentialStore{
		client: client,
		prefix: pathPrefix,
	}, nil
}

// SaveCredential stores a credential in Vault (fail-closed)
func (vcs *VaultCredentialStore) SaveCredential(ctx context.Context, app, username, password string) (string, error) {
	rc := &eos_io.RuntimeContext{
		Ctx:       ctx,
		Timestamp: time.Now(),
	}
	logger := otelzap.Ctx(rc.Ctx)

	// Construct Vault path
	vaultPath := vcs.constructVaultPath(app, username)
	
	// Prepare secret data
	secretData := map[string]interface{}{
		"username": username,
		"password": password,
		"app":      app,
		"metadata": map[string]interface{}{
			"created_by": "eos-xdg",
			"created_at": rc.Timestamp.Format("2006-01-02T15:04:05Z"),
		},
	}

	// Write to Vault
	logger.Debug("Writing credential to Vault",
		zap.String("path", vaultPath),
		zap.String("app", app),
		zap.String("username", username))

	_, err := vcs.client.Logical().Write(vaultPath, map[string]interface{}{
		"data": secretData,
	})
	if err != nil {
		logger.Error("Failed to write credential to Vault",
			zap.Error(err),
			zap.String("path", vaultPath))
		return "", fmt.Errorf("failed to write to vault: %w", err)
	}

	logger.Info("Credential stored successfully in Vault",
		zap.String("path", vaultPath),
		zap.String("app", app),
		zap.String("username", username))

	return vaultPath, nil
}

// ReadCredential retrieves a credential from Vault
func (vcs *VaultCredentialStore) ReadCredential(ctx context.Context, app, username string) (string, error) {
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	logger := otelzap.Ctx(rc.Ctx)

	// Construct Vault path
	vaultPath := vcs.constructVaultPath(app, username)

	logger.Debug("Reading credential from Vault",
		zap.String("path", vaultPath))

	// Read from Vault
	secret, err := vcs.client.Logical().Read(vaultPath)
	if err != nil {
		logger.Error("Failed to read credential from Vault",
			zap.Error(err),
			zap.String("path", vaultPath))
		return "", fmt.Errorf("failed to read from vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		logger.Warn("Credential not found in Vault",
			zap.String("path", vaultPath))
		return "", fmt.Errorf("credential not found")
	}

	// Extract password from KV v2 format
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		// Try KV v1 format
		data = secret.Data
	}

	password, ok := data["password"].(string)
	if !ok {
		logger.Error("Invalid credential format in Vault",
			zap.String("path", vaultPath))
		return "", fmt.Errorf("invalid credential format")
	}

	logger.Info("Credential retrieved successfully from Vault",
		zap.String("path", vaultPath))

	return password, nil
}

// DeleteCredential removes a credential from Vault
func (vcs *VaultCredentialStore) DeleteCredential(ctx context.Context, app, username string) error {
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	logger := otelzap.Ctx(rc.Ctx)

	// Construct Vault path
	vaultPath := vcs.constructVaultPath(app, username)

	logger.Debug("Deleting credential from Vault",
		zap.String("path", vaultPath))

	// Delete from Vault
	_, err := vcs.client.Logical().Delete(vaultPath)
	if err != nil {
		logger.Error("Failed to delete credential from Vault",
			zap.Error(err),
			zap.String("path", vaultPath))
		return fmt.Errorf("failed to delete from vault: %w", err)
	}

	logger.Info("Credential deleted successfully from Vault",
		zap.String("path", vaultPath))

	return nil
}

// ListCredentials lists all credentials for an app
func (vcs *VaultCredentialStore) ListCredentials(ctx context.Context, app string) ([]string, error) {
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	logger := otelzap.Ctx(rc.Ctx)

	// Construct list path
	listPath := fmt.Sprintf("%s/metadata/%s", vcs.prefix, sanitizeVaultPathComponent(app))

	logger.Debug("Listing credentials in Vault",
		zap.String("path", listPath))

	// List from Vault
	secret, err := vcs.client.Logical().List(listPath)
	if err != nil {
		logger.Error("Failed to list credentials from Vault",
			zap.Error(err),
			zap.String("path", listPath))
		return nil, fmt.Errorf("failed to list from vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	// Extract keys
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	usernames := make([]string, 0, len(keys))
	for _, key := range keys {
		if username, ok := key.(string); ok {
			// Remove trailing slash if present
			username = strings.TrimSuffix(username, "/")
			usernames = append(usernames, username)
		}
	}

	logger.Info("Listed credentials from Vault",
		zap.String("app", app),
		zap.Int("count", len(usernames)))

	return usernames, nil
}

// constructVaultPath builds the Vault path for a credential
func (vcs *VaultCredentialStore) constructVaultPath(app, username string) string {
	// Sanitize components to prevent path traversal
	safeApp := sanitizeVaultPathComponent(app)
	safeUsername := sanitizeVaultPathComponent(username)
	
	// Use KV v2 data path
	return fmt.Sprintf("%s/data/%s/%s", vcs.prefix, safeApp, safeUsername)
}

// sanitizeVaultPathComponent removes dangerous characters from Vault path components
// SECURITY: Prevents path traversal via Unicode normalization, filepath.Clean, and whitelist validation
func sanitizeVaultPathComponent(component string) string {
	// CRITICAL: Unicode normalization prevents attacks like:
	// "..%c0%af" → "../" after normalization
	// "..%e0%80%af" → "../" (overlong UTF-8)
	component = norm.NFC.String(component)

	// Remove null bytes (directory traversal in some filesystems)
	component = strings.ReplaceAll(component, "\x00", "")
	component = strings.TrimSpace(component)

	// Reject if empty after normalization
	if component == "" {
		return "invalid"
	}

	// CRITICAL: Use filepath.Clean to resolve ".." and "." before validation
	// This prevents "a/../../etc/passwd" → "etc/passwd" attacks
	component = filepath.Clean(component)

	// CRITICAL: Reject if contains path traversal after cleaning
	if strings.Contains(component, "..") {
		return "invalid"
	}

	// CRITICAL: Reject absolute paths
	if strings.HasPrefix(component, "/") || strings.HasPrefix(component, "\\") {
		return "invalid"
	}

	// CRITICAL: Filter to alphanumeric, dash, underscore only
	// This prevents all special characters that could be used for traversal
	var safe strings.Builder
	safe.Grow(len(component))

	for _, r := range component {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			safe.WriteRune(r)
		} else if r == '-' || r == '_' || r == '.' {
			// Allow limited special chars
			safe.WriteRune(r)
		} else {
			// Replace everything else with dash
			safe.WriteRune('-')
		}
	}

	result := safe.String()

	// Final validation: No ".." should exist
	if strings.Contains(result, "..") {
		return "invalid"
	}

	// Prevent empty result
	if result == "" || result == "." || result == "-" {
		return "invalid"
	}

	return result
}

// Ensure VaultCredentialStore implements xdg.CredentialStore
var _ xdg.CredentialStore = (*VaultCredentialStore)(nil)