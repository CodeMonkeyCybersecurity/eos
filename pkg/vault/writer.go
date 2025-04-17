/* pkg/vault/writer.go */

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
// === Vault Write Helpers ===
//

// Write stores a struct in Vault using the API or falls back to disk if Vault is unavailable.
// If client is nil, it initializes one automatically.
func Write(client *api.Client, name string, data any, log *zap.Logger) error {
	var err error
	if client == nil {
		client, err = NewClient(log)
		if err != nil {
			log.Warn("Vault client creation failed", zap.Error(err))
			return writeToDisk(name, data, log)
		}
	}

	SetVaultClient(client, log)
	path := vaultPath(name, log)

	if err := WriteToVault(path, data, log); err == nil {
		log.Info("✅ Vault secret written", zap.String("path", path))
		return nil
	}

	log.Warn("⚠️ Vault API write failed", zap.String("path", path), zap.Error(err))

	if err := WriteToVault(path, data, log); err == nil {
		log.Info("✅ Vault secret written", zap.String("path", path))
		return nil
	}
	log.Warn("⚠️ Vault API write failed", zap.String("path", path), zap.Error(err))
	return writeToDisk(name, data, log)
}

// WriteToVault stores a serializable struct to Vault at a given KV v2 path.
func WriteToVault(path string, v interface{}, log *zap.Logger) error {
	return WriteToVaultAt("secret", path, v, log)
}

func WriteToVaultAt(mount, path string, v interface{}, log *zap.Logger) error {
	client, err := GetVaultClient(log)
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

func writeToDisk(name string, data any, log *zap.Logger) error {
	fallbackPath := DiskPath(name, log)
	log.Info("💾 Falling back to local disk", zap.String("path", fallbackPath))
	return WriteFallbackJSON(fallbackPath, data)
}
