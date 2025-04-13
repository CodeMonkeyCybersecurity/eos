/* pkg/vault/writer.go */

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/vault/api"
)

//
// === Vault Write Helpers ===
//

func WriteAuto(path string, data any) error {
	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}
	return Write(client, path, data)
}

// Write stores a struct in Vault using the API or falls back to disk if the API call fails.
func Write(client *api.Client, name string, data any) error {
	SetVaultClient(client)
	path := vaultPath(name) // ✅ fix: removed invalid argument

	if err := WriteToVault(path, data); err == nil {
		fmt.Println("✅ Vault secret written:", path)
		return nil
	}

	fmt.Println("⚠️ Vault API write failed for:", path)
	fmt.Println("💾 Falling back to local disk:", DiskPath(name))
	return WriteFallbackJSON(DiskPath(name), data)
}

// WriteToVault stores a serializable struct to Vault at a given KV v2 path.
func WriteToVault(path string, v interface{}) error {
	return WriteToVaultAt("secret", path, v)
}

func WriteToVaultAt(mount, path string, v interface{}) error {
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

// WriteSecret writes a raw map directly to Vault.
func WriteSecret(client *api.Client, path string, data map[string]interface{}) error {
	_, err := client.Logical().Write(path, data)
	return err
}

//
// === Fallback (JSON) Helpers ===
//

// WriteFallbackJSON saves any struct as JSON to the given path (used for Vault fallback or CLI secrets).
func WriteFallbackJSON(path string, data any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create fallback directory: %w", err)
	}

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal fallback JSON: %w", err)
	}

	if err := os.WriteFile(path, b, 0600); err != nil {
		return fmt.Errorf("write fallback file: %w", err)
	}

	fmt.Printf("✅ Fallback data saved to %s\n", path)
	fmt.Println("💡 Run `eos vault sync` later to upload it to Vault.")
	return nil
}
