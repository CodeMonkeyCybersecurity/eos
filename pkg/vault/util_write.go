// pkg/vault/writer.go

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Write stores a struct in Vault using the API or falls back to disk if Vault is unavailable.
// If client is nil, it initializes one automatically.
func Write(rc *eos_io.RuntimeContext, client *api.Client, name string, data any) error {
	var err error
	if client == nil {
		client, err = GetVaultClient(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Vault client creation failed", zap.Error(err))
			return WriteToDisk(rc, name, data)
		}
	}

	SetVaultClient(rc, client)
	path := VaultPath(rc, name)

	if err := WriteToVault(rc, path, data); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Vault write failed — falling back to disk", zap.String("path", path), zap.Error(err))
		return WriteToDisk(rc, name, data)
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault secret written", zap.String("path", path))
	return nil
}

// WriteToVault stores a serializable struct to Vault at a given KV v2 path.
func WriteToVault(rc *eos_io.RuntimeContext, path string, v interface{}) error {
	return WriteToVaultAt(rc, shared.VaultMountKV, path, v)
}

// WriteToVaultAt writes a serialized object to a specific Vault mount path using the KVv2 API.
func WriteToVaultAt(rc *eos_io.RuntimeContext, mount, path string, v interface{}) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug(" Entering WriteToVaultAt",
		zap.String("mount", mount),
		zap.String("path", path))

	// CRITICAL P0: Try to get existing client from context first
	// This prevents re-authentication during initial setup when we already have a root token
	var client *api.Client
	if cachedClient, ok := rc.Ctx.Value(vaultClientKey).(*api.Client); ok && cachedClient != nil && cachedClient.Token() != "" {
		client = cachedClient
		logger.Debug(" Using cached Vault client from RuntimeContext for write operation",
			zap.String("vault_addr", client.Address()),
			zap.Bool("has_token", true),
			zap.String("source", "context cache"))
	} else {
		// No client in context - create authenticated one
		logger.Debug(" No cached client in context, creating authenticated client",
			zap.String("reason", "Will trigger authentication flow"))
		var err error
		client, err = GetVaultClient(rc)
		if err != nil {
			logger.Error(" Failed to get authenticated Vault client",
				zap.Error(err),
				zap.String("remediation", "Check authentication credentials"))
			return fmt.Errorf("get vault client: %w", err)
		}
		logger.Debug(" Authenticated client created successfully")
	}

	logger.Debug(" Marshaling data to JSON for Vault storage")
	data, err := json.Marshal(v)
	if err != nil {
		logger.Error(" Failed to marshal data to JSON",
			zap.Error(err),
			zap.String("path", path))
		return fmt.Errorf("failed to marshal struct: %w", err)
	}
	logger.Debug(" Data marshaled successfully",
		zap.Int("json_bytes", len(data)))

	logger.Debug(" Writing data to Vault KV v2",
		zap.String("mount", mount),
		zap.String("path", path),
		zap.Int("data_size_bytes", len(data)))

	kv := client.KVv2(mount)
	_, err = kv.Put(context.Background(), path, map[string]interface{}{
		"json": string(data),
	})
	if err != nil {
		logger.Error(" Failed to write data to Vault KV",
			zap.Error(err),
			zap.String("mount", mount),
			zap.String("path", path),
			zap.String("vault_addr", client.Address()),
			zap.String("remediation", "Check Vault permissions and KV mount exists"))
		return fmt.Errorf("vault kv put failed at %s/%s: %w", mount, path, err)
	}

	logger.Info(" Data written to Vault KV successfully",
		zap.String("mount", mount),
		zap.String("path", path),
		zap.Int("data_size_bytes", len(data)))
	return nil
}

// WriteFallbackSecrets securely stores secrets as JSON in the XDG config directory for later retrieval.
func WriteFallbackSecrets(rc *eos_io.RuntimeContext, name string, secrets map[string]string) error {
	path := xdg.XDGConfigPath(shared.EosID, filepath.Join(name, "config.json"))
	otelzap.Ctx(rc.Ctx).Debug("Writing fallback secrets", zap.String("path", path))

	if err := os.MkdirAll(filepath.Dir(path), VaultDataDirPerm); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal fallback secrets: %w", err)
	}
	if err := os.WriteFile(path, data, VaultSecretFilePerm); err != nil {
		return fmt.Errorf("write fallback secrets: %w", err)
	}
	return nil
}

// WriteSecret writes a raw key-value map to a Vault logical path without serialization.
func WriteSecret(rc *eos_io.RuntimeContext, client *api.Client, path string, data map[string]interface{}) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Writing secret to Vault",
		zap.String("path", path),
		zap.Int("data_keys", len(data)))

	_, err := client.Logical().Write(path, data)
	if err != nil {
		logger.Error("Failed to write secret to Vault",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("failed to write raw secret to Vault at path %q: %w", path, err)
	}

	logger.Info("Successfully wrote secret to Vault", zap.String("path", path))
	return nil
}

//
// === Fallback (JSON) Helpers ===
//

// WriteFallbackJSON saves any struct as JSON to the given path (used for Vault fallback or CLI secrets).
func WriteFallbackJSON(rc *eos_io.RuntimeContext, path string, data any) error {
	if err := os.MkdirAll(filepath.Dir(path), VaultDataDirPerm); err != nil {
		return fmt.Errorf("create fallback directory: %w", err)
	}

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal fallback JSON: %w", err)
	}

	if err := os.WriteFile(path, b, VaultSecretFilePerm); err != nil {
		return fmt.Errorf("write fallback file: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Fallback data saved", zap.String("path", path))
	otelzap.Ctx(rc.Ctx).Info(" Run `eos vault sync` later to upload to Vault")
	return nil
}

// is used as a fallback if Vault is unavailable. It saves structured data to a JSON file on disk.
func WriteToDisk(rc *eos_io.RuntimeContext, name string, data any) error {
	fallbackPath := DiskPath(rc, name)
	otelzap.Ctx(rc.Ctx).Info(" Falling back to local disk", zap.String("path", fallbackPath))
	return WriteFallbackJSON(rc, fallbackPath, data)
}

// WriteKVv2 writes a payload to a Vault KV v2 mount at the given logical path.
// It handles the /data/ prefix required by KVv2 automatically.
func WriteKVv2(rc *eos_io.RuntimeContext, client *api.Client, mount string, path string, data map[string]interface{}) error {
	otelzap.Ctx(rc.Ctx).Info(" Writing KVv2 secret",
		zap.String("mount", mount),
		zap.String("path", path),
		zap.Any("data_keys", keysOf(data)),
	)

	kv := client.KVv2(strings.TrimSuffix(mount, "/"))
	if _, err := kv.Put(context.Background(), path, data); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to write KVv2 secret",
			zap.String("mount", mount),
			zap.String("path", path),
			zap.Error(err),
		)
		return fmt.Errorf("failed to write KVv2 secret at %s/%s: %w", mount, path, err)
	}

	otelzap.Ctx(rc.Ctx).Info(" KVv2 secret written successfully",
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
func Delete(rc *eos_io.RuntimeContext, client *api.Client, path string) error {
	if client == nil {
		return fmt.Errorf("vault client is nil")
	}

	otelzap.Ctx(rc.Ctx).Info(" Deleting secret from Vault", zap.String("path", path))

	kv := client.KVv2("secret") // Assuming your KV mount is "secret/"

	// ❗ Correct: manually provide context.Background()
	err := kv.Delete(context.Background(), path)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to delete Vault secret", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("vault delete failed: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault secret deleted", zap.String("path", path))
	return nil
}

// writeTestDataToVaultOrFallback writes test data into Vault or falls back to disk storage if Vault is unavailable.
func WriteTestDataToVaultOrFallback(rc *eos_io.RuntimeContext, client *api.Client, data map[string]interface{}) error {
	otelzap.Ctx(rc.Ctx).Info(" Attempting to write test data into Vault...")

	vaultPath := "test-data" // Adjust if you want "eos/test-data" instead
	vaultErr := Write(rc, client, vaultPath, data)

	if vaultErr == nil {
		otelzap.Ctx(rc.Ctx).Info(" Uploaded test-data into Vault", zap.String("vault_path", vaultPath))
		PrintStorageSummary(rc, "Vault", vaultPath, "SUCCESS", "Disk", "N/A")
		return nil
	}

	otelzap.Ctx(rc.Ctx).Warn("Vault write failed — falling back to disk", zap.Error(vaultErr))

	outputPath := diskFallbackPath()
	if err := os.MkdirAll(filepath.Dir(outputPath), shared.RuntimeDirPerms); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to create output directory", zap.String("path", outputPath), zap.Error(err))
		PrintStorageSummary(rc, "Vault", vaultPath, "FAILED", "Disk", "FAILED")
		return fmt.Errorf("vault write failed: %w; fallback mkdir failed: %v", vaultErr, err)
	}

	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to marshal test data", zap.Error(err))
		PrintStorageSummary(rc, "Vault", vaultPath, "FAILED", "Disk", "FAILED")
		return fmt.Errorf("vault write failed: %w; fallback marshal failed: %v", vaultErr, err)
	}

	if err := os.WriteFile(outputPath, raw, shared.RuntimeFilePerms); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to write fallback test data", zap.String("path", outputPath), zap.Error(err))
		PrintStorageSummary(rc, "Vault", vaultPath, "FAILED", "Disk", "FAILED")
		return fmt.Errorf("vault write failed: %w; fallback disk write failed: %v", vaultErr, err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Fallback to disk succeeded", zap.String("disk_path", outputPath))
	PrintStorageSummary(rc, "Vault", vaultPath, "FAILED", "Disk", "SUCCESS")
	return nil
}

// WriteUserpassPasswordToVault writes the userpass password to Vault KV
func WriteUserpassPasswordToVault(rc *eos_io.RuntimeContext, client *api.Client, password string) error {
	return WriteKVv2(rc, client, shared.VaultSecretMount, shared.UserpassKVPath, shared.FallbackSecretsTemplate(password))
}

// WriteSSHKey stores an SSH key pair in Vault KV-v2 and
// attaches the fingerprint as custom metadata (v1.16.0 client).
func WriteSSHKey(
	rc *eos_io.RuntimeContext, // rc contains the context you need!
	client *api.Client,
	mount, path, pub, priv, fingerprint string,
) error {
	if client == nil {
		return fmt.Errorf("vault client is nil")
	}

	kv := client.KVv2(mount)

	//  Write public/private key data
	// CHANGE THIS LINE: Use rc.Ctx instead of nil
	if _, err := kv.Put(rc.Ctx, path, map[string]interface{}{
		"ssh_public":  pub,
		"ssh_private": priv,
	}); err != nil {
		return fmt.Errorf("failed to write SSH key data at %s/%s: %w",
			mount, path, err)
	}
	otelzap.Ctx(rc.Ctx).Info(" SSH key data written",
		zap.String("mount", mount), zap.String("path", path),
	)

	//  Write fingerprint into metadata via the logical client
	metaPath := fmt.Sprintf("%s/metadata/%s", mount, path)
	// You also need to pass the context here for client.Logical().Write()
	_, err := client.Logical().WriteWithContext(rc.Ctx, metaPath, map[string]interface{}{ // Use WriteWithContext
		"custom_metadata": map[string]string{
			"fingerprint": fingerprint,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to write SSH fingerprint metadata at %s/%s: %w",
			mount, path, err)
	}
	otelzap.Ctx(rc.Ctx).Info(" SSH fingerprint metadata written",
		zap.String("mount", mount), zap.String("path", metaPath),
	)

	return nil
}
