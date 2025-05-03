// pkg/vault/writer.go

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// Write stores a struct in Vault using the API or falls back to disk if Vault is unavailable.
// If client is nil, it initializes one automatically.
func Write(client *api.Client, name string, data any) error {
	var err error
	if client == nil {
		client, err = NewClient()
		if err != nil {
			zap.L().Warn("Vault client creation failed", zap.Error(err))
			return WriteToDisk(name, data)
		}
	}

	SetVaultClient(client)
	path := VaultPath(name)

	if err := WriteToVault(path, data); err != nil {
		zap.L().Warn("⚠️ Vault write failed — falling back to disk", zap.String("path", path), zap.Error(err))
		return WriteToDisk(name, data)
	}

	zap.L().Info("✅ Vault secret written", zap.String("path", path))
	return nil
}

// WriteToVault stores a serializable struct to Vault at a given KV v2 path.
func WriteToVault(path string, v interface{}) error {
	return WriteToVaultAt(shared.VaultMountKV, path, v)
}

// WriteToVaultAt writes a serialized object to a specific Vault mount path using the KVv2 API.
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

// WriteFallbackSecrets securely stores secrets as JSON in the XDG config directory for later retrieval.
func WriteFallbackSecrets(name string, secrets map[string]string) error {
	path := xdg.XDGConfigPath(shared.EosID, filepath.Join(name, "config.json"))
	zap.L().Debug("Writing fallback secrets", zap.String("path", path))

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal fallback secrets: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write fallback secrets: %w", err)
	}
	return nil
}

// WriteSecret writes a raw key-value map to a Vault logical path without serialization.
func WriteSecret(client *api.Client, path string, data map[string]interface{}) error {
	_, err := client.Logical().Write(path, data)
	return fmt.Errorf("failed to write raw secret to Vault at path %q: %w", path, err)
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

	zap.L().Info("✅ Fallback data saved", zap.String("path", path))
	zap.L().Info("💡 Run `eos vault sync` later to upload to Vault")
	return nil
}

// is used as a fallback if Vault is unavailable. It saves structured data to a JSON file on disk.
func WriteToDisk(name string, data any) error {
	fallbackPath := DiskPath(name)
	zap.L().Info("💾 Falling back to local disk", zap.String("path", fallbackPath))
	return WriteFallbackJSON(fallbackPath, data)
}

// WriteKVv2 writes a payload to a Vault KV v2 mount at the given logical path.
// It handles the /data/ prefix required by KVv2 automatically.
func WriteKVv2(client *api.Client, mount string, path string, data map[string]interface{}) error {
	zap.L().Info("🔃 Writing KVv2 secret",
		zap.String("mount", mount),
		zap.String("path", path),
		zap.Any("data_keys", keysOf(data)),
	)

	kv := client.KVv2(strings.TrimSuffix(mount, "/"))
	if _, err := kv.Put(context.Background(), path, data); err != nil {
		zap.L().Error("❌ Failed to write KVv2 secret",
			zap.String("mount", mount),
			zap.String("path", path),
			zap.Error(err),
		)
		return fmt.Errorf("failed to write KVv2 secret at %s/%s: %w", mount, path, err)
	}

	zap.L().Info("✅ KVv2 secret written successfully",
		zap.String("mount", mount),
		zap.String("path", path),
	)
	return nil
}

// helper for debugging: list keys in a map
func keysOf(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Delete removes a secret at the given path in Vault KV v2.
// It expects a valid client, and a path relative to the KV mount.
func Delete(client *api.Client, path string) error {
	if client == nil {
		return fmt.Errorf("vault client is nil")
	}

	zap.L().Info("🗑️ Deleting secret from Vault", zap.String("path", path))

	kv := client.KVv2("secret") // Assuming your KV mount is "secret/"

	// ❗ Correct: manually provide context.Background()
	err := kv.Delete(context.Background(), path)
	if err != nil {
		zap.L().Error("❌ Failed to delete Vault secret", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("vault delete failed: %w", err)
	}

	zap.L().Info("✅ Vault secret deleted", zap.String("path", path))
	return nil
}
