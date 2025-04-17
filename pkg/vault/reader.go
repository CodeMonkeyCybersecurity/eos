/* pkg/vault/reader.go */

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//
// === Vault Read Helpers ===
//

// ReadFromVault loads a struct from a Vault KV v2 path (default mount "secret").
func ReadFromVault(path string, out interface{}) error {
	return ReadFromVaultAt(context.Background(), "secret", path, out)
}

// ReadFromVaultAt loads a struct from a custom KV v2 mount.
func ReadFromVaultAt(ctx context.Context, mount, path string, out interface{}) error {
	client, err := GetVaultClient()
	if err != nil {
		return fmt.Errorf("unable to get Vault client: %w", err)
	}

	kv := client.KVv2(mount)
	secret, err := kv.Get(ctx, path)
	if err != nil {
		return fmt.Errorf("vault API read failed at %q: %w", path, err)
	}

	raw, ok := secret.Data["json"].(string)
	if !ok {
		return fmt.Errorf("malformed or missing 'json' field at path %q", path)
	}

	if err := json.Unmarshal([]byte(raw), out); err != nil {
		return fmt.Errorf("failed to unmarshal secret JSON at %q: %w", path, err)
	}
	return nil
}

// Read loads a namespaced config from Vault, or falls back to YAML if unavailable.
func Read(client *api.Client, name string, out any, log *zap.Logger) error {
	if IsVaultAvailable(client, log) {
		err := ReadFromVaultAt(context.Background(), "secret", name, out)
		if err == nil {
			return nil
		}
		fmt.Printf("⚠️  Vault read failed for %q: %v\n", name, err)
		fmt.Println("💡 Falling back to local config...")
	}
	return ReadFallbackIntoJSON(DiskPath(name, log), out)
}

//
// === Fallback Read Helpers ===
//

// ReadFallbackJSON reads any struct from JSON at the given path.
func ReadFallbackJSON[T any](path string) (*T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fallback JSON: %w", err)
	}

	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("unmarshal fallback JSON: %w", err)
	}

	return &result, nil
}

// readFallbackSecrets loads fallback secrets for Delphi (or other shared secrets).
func ReadFallbackSecrets() (map[string]string, error) {
	path := filepath.Join(SecretsDir, "delphi-fallback.yaml")

	secretsPtr, err := ReadFallbackJSON[map[string]string](path)
	if err != nil {
		return nil, fmt.Errorf("could not load fallback secrets from %s: %w", path, err)
	}

	fmt.Printf("📥 Fallback credentials loaded from %s\n", path)
	return *secretsPtr, nil
}

func ReadFallbackIntoJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read fallback JSON: %w", err)
	}
	return json.Unmarshal(data, out)
}

func ListUnder(path string) ([]string, error) {
	client, err := GetPrivilegedVaultClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get Vault client: %w", err)
	}

	list, err := client.Logical().List("secret/metadata/" + path)
	if err != nil {
		return nil, fmt.Errorf("vault list failed: %w", err)
	}
	if list == nil || list.Data == nil {
		return nil, fmt.Errorf("no data found at secret/metadata/%s", path)
	}

	raw, ok := list.Data["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected Vault list format")
	}

	keys := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			keys = append(keys, s)
		}
	}
	return keys, nil
}
