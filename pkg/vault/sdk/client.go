// pkg/vault/sdk/client.go
//
// Vault SDK client utilities and KV helpers.
// Provides centralized SDK access patterns to replace shell command executions.
//
// Last Updated: 2025-01-25

package sdk

import (
	"context"
	"encoding/json"
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewClient creates a new Vault API client with default configuration.
// Uses environment variables for configuration (VAULT_ADDR, VAULT_TOKEN, etc.)
func NewClient() (*vaultapi.Client, error) {
	config := vaultapi.DefaultConfig()
	if err := config.ReadEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to read Vault environment: %w", err)
	}

	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}
	return client, nil
}

// NewClientWithConfig creates a Vault client with custom configuration.
func NewClientWithConfig(config *vaultapi.Config) (*vaultapi.Client, error) {
	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}
	return client, nil
}

// KVGetField retrieves a specific field from a KV v2 secret.
// Replaces: vault kv get -field=<field> <path>
// Returns empty string if field doesn't exist (not an error).
func KVGetField(ctx context.Context, client *vaultapi.Client, path, field string) (string, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Retrieving KV field from Vault",
		zap.String("path", path),
		zap.String("field", field))

	// For KV v2, the actual API path is different from the CLI path
	// CLI: secret/myapp
	// API: secret/data/myapp
	apiPath := convertKVPath(path)

	secret, err := client.Logical().Read(apiPath)
	if err != nil {
		return "", fmt.Errorf("failed to read secret %s: %w", path, err)
	}

	if secret == nil || secret.Data == nil {
		logger.Debug("Secret not found", zap.String("path", path))
		return "", nil
	}

	// KV v2 stores data under the "data" key
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid secret format at %s", path)
	}

	value, ok := data[field]
	if !ok {
		logger.Debug("Field not found in secret",
			zap.String("path", path),
			zap.String("field", field))
		return "", nil
	}

	valueStr, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("field %s is not a string", field)
	}

	logger.Debug("KV field retrieved successfully",
		zap.String("path", path),
		zap.String("field", field))

	return valueStr, nil
}

// KVGet retrieves an entire KV v2 secret.
// Replaces: vault kv get <path>
// Returns nil if secret does not exist (not an error).
func KVGet(ctx context.Context, client *vaultapi.Client, path string) (map[string]interface{}, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Retrieving KV secret from Vault", zap.String("path", path))

	apiPath := convertKVPath(path)

	secret, err := client.Logical().Read(apiPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret %s: %w", path, err)
	}

	if secret == nil || secret.Data == nil {
		logger.Debug("Secret not found", zap.String("path", path))
		return nil, nil
	}

	// KV v2 stores data under the "data" key
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid secret format at %s", path)
	}

	logger.Debug("KV secret retrieved successfully",
		zap.String("path", path),
		zap.Int("field_count", len(data)))

	return data, nil
}

// KVGetJSON retrieves a KV v2 secret and returns it as JSON.
// Replaces: vault kv get -format=json <path>
func KVGetJSON(ctx context.Context, client *vaultapi.Client, path string) ([]byte, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Retrieving KV secret as JSON", zap.String("path", path))

	data, err := KVGet(ctx, client, path)
	if err != nil {
		return nil, err
	}

	if data == nil {
		return nil, fmt.Errorf("secret not found: %s", path)
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secret to JSON: %w", err)
	}

	logger.Debug("KV secret marshaled to JSON",
		zap.String("path", path),
		zap.Int("json_size", len(jsonData)))

	return jsonData, nil
}

// KVPut stores a KV v2 secret.
// Replaces: vault kv put <path> key=value ...
func KVPut(ctx context.Context, client *vaultapi.Client, path string, data map[string]interface{}) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Storing KV secret in Vault",
		zap.String("path", path),
		zap.Int("field_count", len(data)))

	apiPath := convertKVPath(path)

	// KV v2 requires data to be wrapped in a "data" key
	wrappedData := map[string]interface{}{
		"data": data,
	}

	_, err := client.Logical().Write(apiPath, wrappedData)
	if err != nil {
		return fmt.Errorf("failed to write secret %s: %w", path, err)
	}

	logger.Debug("KV secret stored successfully", zap.String("path", path))

	return nil
}

// KVDelete deletes a KV v2 secret (latest version).
// Replaces: vault kv delete <path>
func KVDelete(ctx context.Context, client *vaultapi.Client, path string) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Deleting KV secret from Vault", zap.String("path", path))

	apiPath := convertKVPath(path)

	_, err := client.Logical().Delete(apiPath)
	if err != nil {
		return fmt.Errorf("failed to delete secret %s: %w", path, err)
	}

	logger.Debug("KV secret deleted successfully", zap.String("path", path))

	return nil
}

// KVList lists secrets at a given path.
// Replaces: vault kv list <path>
// Returns empty slice if no secrets exist (not an error).
func KVList(ctx context.Context, client *vaultapi.Client, path string) ([]string, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Listing KV secrets", zap.String("path", path))

	// For KV v2 list operations, use metadata path
	apiPath := convertKVListPath(path)

	secret, err := client.Logical().List(apiPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets at %s: %w", path, err)
	}

	if secret == nil || secret.Data == nil {
		logger.Debug("No secrets found at path", zap.String("path", path))
		return []string{}, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	result := make([]string, 0, len(keys))
	for _, key := range keys {
		if keyStr, ok := key.(string); ok {
			result = append(result, keyStr)
		}
	}

	logger.Debug("KV secrets listed successfully",
		zap.String("path", path),
		zap.Int("count", len(result)))

	return result, nil
}

// PolicyList lists all policies in Vault.
// Replaces: vault policy list
func PolicyList(ctx context.Context, client *vaultapi.Client) ([]string, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Listing Vault policies")

	policies, err := client.Sys().ListPolicies()
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}

	logger.Debug("Policies listed successfully", zap.Int("count", len(policies)))

	return policies, nil
}

// PolicyRead retrieves a policy by name.
// Replaces: vault policy read <name>
func PolicyRead(ctx context.Context, client *vaultapi.Client, name string) (string, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Reading Vault policy", zap.String("name", name))

	policy, err := client.Sys().GetPolicy(name)
	if err != nil {
		return "", fmt.Errorf("failed to read policy %s: %w", name, err)
	}

	logger.Debug("Policy read successfully",
		zap.String("name", name),
		zap.Int("policy_size", len(policy)))

	return policy, nil
}

// PolicyWrite creates or updates a policy.
// Replaces: vault policy write <name> <policy>
func PolicyWrite(ctx context.Context, client *vaultapi.Client, name, policy string) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Writing Vault policy",
		zap.String("name", name),
		zap.Int("policy_size", len(policy)))

	if err := client.Sys().PutPolicy(name, policy); err != nil {
		return fmt.Errorf("failed to write policy %s: %w", name, err)
	}

	logger.Debug("Policy written successfully", zap.String("name", name))

	return nil
}

// Helper functions

// convertKVPath converts a KV v2 CLI path to the API path.
// CLI path: secret/myapp
// API path: secret/data/myapp
func convertKVPath(path string) string {
	// Simple heuristic: if path starts with "secret/", inject "data/"
	// More robust implementation would check mount type
	if len(path) > 7 && path[:7] == "secret/" {
		return "secret/data/" + path[7:]
	}
	return path
}

// convertKVListPath converts a KV v2 CLI list path to the API path.
// CLI path: secret/myapp
// API path: secret/metadata/myapp
func convertKVListPath(path string) string {
	// Simple heuristic: if path starts with "secret/", inject "metadata/"
	if len(path) > 7 && path[:7] == "secret/" {
		return "secret/metadata/" + path[7:]
	}
	return path
}
