/* pkg/vault/reader.go */

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v3"
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
func Read(client *api.Client, name string, out any) error {
	if IsVaultAvailable(client) {
		err := ReadFromVaultAt(context.Background(), "secret", name, out)
		if err == nil {
			return nil
		}
		fmt.Printf("⚠️  Vault read failed for %q: %v\n", name, err)
		fmt.Println("💡 Falling back to local config...")
	}
	return readFallbackYAML(diskPath(name), out)
}

//
// === Fallback Read Helpers ===
//

func readFallbackYAML(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read fallback file %q: %w", path, err)
	}
	if err := yaml.Unmarshal(b, out); err != nil {
		return fmt.Errorf("failed to parse fallback YAML at %q: %w", path, err)
	}
	return nil
}

func readFallbackMap(name string) (map[string]string, error) {
	var data map[string]string
	path := filepath.Join(diskSecretsPath, name)
	err := readFallbackYAML(path, &data)
	if err != nil {
		return nil, fmt.Errorf("could not load fallback secrets from %s: %w", path, err)
	}
	fmt.Printf("📥 Fallback secrets loaded from %s\n", path)
	return data, nil
}

// readFallbackSecrets loads fallback secrets for Delphi (or other shared secrets).
func readFallbackSecrets() (map[string]string, error) {
	var secrets map[string]string
	path := filepath.Join(diskSecretsPath, "delphi-fallback.yaml")

	err := readFallbackYAML(path, &secrets)
	if err != nil {
		return nil, fmt.Errorf("could not load fallback secrets from %s: %w", path, err)
	}
	fmt.Printf("📥 Fallback credentials loaded from %s\n", path)
	return secrets, nil
}
