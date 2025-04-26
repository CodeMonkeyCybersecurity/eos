// pkg/vault/writer.go

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// Write stores a struct in Vault using the API or falls back to disk if Vault is unavailable.
// If client is nil, it initializes one automatically.
func Write(client *api.Client, name string, data any, log *zap.Logger) error {
	var err error
	if client == nil {
		client, err = NewClient(log)
		if err != nil {
			log.Warn("Vault client creation failed", zap.Error(err))
			return WriteToDisk(name, data, log)
		}
	}

	SetVaultClient(client, log)
	path := VaultPath(name, log)

	if err := WriteToVault(path, data, log); err != nil {
		log.Warn("⚠️ Vault write failed — falling back to disk", zap.String("path", path), zap.Error(err))
		return WriteToDisk(name, data, log)
	}

	log.Info("✅ Vault secret written", zap.String("path", path))
	return nil
}

// WriteToVault stores a serializable struct to Vault at a given KV v2 path.
func WriteToVault(path string, v interface{}, log *zap.Logger) error {
	return WriteToVaultAt(shared.VaultMountKV, path, v, log)
}

// WriteToVaultAt writes a serialized object to a specific Vault mount path using the KVv2 API.
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

// WriteFallbackSecrets securely stores secrets as JSON in the XDG config directory for later retrieval.
func WriteFallbackSecrets(name string, secrets map[string]string, log *zap.Logger) error {
	path := xdg.XDGConfigPath(shared.EosID, filepath.Join(name, "config.json"))
	log.Debug("Writing fallback secrets", zap.String("path", path))

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
func WriteFallbackJSON(path string, data any, log *zap.Logger) error {
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

	log.Info("✅ Fallback data saved", zap.String("path", path))
	log.Info("💡 Run `eos vault sync` later to upload to Vault")
	return nil
}

// is used as a fallback if Vault is unavailable. It saves structured data to a JSON file on disk.
func WriteToDisk(name string, data any, log *zap.Logger) error {
	fallbackPath := DiskPath(name, log)
	log.Info("💾 Falling back to local disk", zap.String("path", fallbackPath))
	return WriteFallbackJSON(fallbackPath, data, log)
}
