/* pkg/vault/writer.go */

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
// === Vault Write Helpers ===
//

// Save stores a struct in Vault using the API or falls back to disk if the API call fails.
func Save(client *api.Client, name string, data any) error {
	SetVaultClient(client)
	path := vaultPath(name)

	if err := SaveToVault(path, data); err == nil {
		return nil
	}

	fmt.Println("⚠️ Vault API write failed — falling back to disk:")
	return writeFallbackYAML(diskPath(name), data)
}

// SaveToVault stores a serializable struct to Vault at a given KV v2 path.
func SaveToVault(path string, v interface{}) error {
	return SaveToVaultAt("secret", path, v)
}

func SaveToVaultAt(mount, path string, v interface{}) error {
	client, err := GetVaultClient()
	if err != nil {
		return err
	}

	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal struct: %w", err)
	}

	kv := client.KVv2(mount)
	_, err = kv.Put(context.Background(), path, map[string]interface{}{
		"json": string(data),
	})
	return err
}

// SaveSecret writes a raw map directly to Vault.
func SaveSecret(client *api.Client, path string, data map[string]interface{}) error {
	_, err := client.Logical().Write(path, data)
	return err
}

//
// === Fallback (YAML) Helpers ===
//

// writeFallbackYAML writes any struct as YAML to a fallback path on disk.
func writeFallbackYAML(path string, data any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create fallback directory: %w", err)
	}

	b, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal fallback data: %w", err)
	}

	if err := os.WriteFile(path, b, 0600); err != nil {
		return fmt.Errorf("write fallback file: %w", err)
	}

	fmt.Printf("✅ Fallback data saved to %s\n", path)
	fmt.Println("💡 Run `eos vault sync` later to upload it to Vault.")
	return nil
}

func writeFallbackSecrets(secrets map[string]string) error {
	return writeFallbackYAML(fallbackSecretsPath, secrets)
}
