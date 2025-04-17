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

// Read loads a namespaced config from Vault, or falls back to YAML if unavailable.
func Read(client *api.Client, name string, out any, log *zap.Logger) error {
	report, client := Check(client, log, nil, "")
	if client == nil {
		return fmt.Errorf("vault client is not ready")
	}
	if report.Initialized && !report.Sealed {
		err := ReadFromVaultAt(context.Background(), "secret", name, out, log)
		if err == nil {
			return nil
		}
		log.Warn("Vault read failed, falling back", zap.String("path", name), zap.Error(err))
	}

	return ReadFallbackIntoJSON(DiskPath(name, log), out, log)
}

// ReadFromVault loads a struct from a Vault KV v2 path (default mount "secret").
func ReadFromVault(path string, out interface{}, log *zap.Logger) error {
	return ReadFromVaultAt(context.Background(), "secret", path, out, log)
}

// ReadFromVaultAt loads a struct from a custom KV v2 mount.
func ReadFromVaultAt(ctx context.Context, mount, path string, out interface{}, log *zap.Logger) error {
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

//
// === Fallback Read Helpers ===
//

// ReadFallbackJSON reads any struct from JSON at the given path.
func ReadFallbackJSON[T any](path string, log *zap.Logger) (*T, error) {
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

// ReadFallbackSecrets loads fallback secrets for Delphi (or other shared secrets).
func ReadFallbackSecrets(log *zap.Logger) (map[string]string, error) {
	path := filepath.Join(SecretsDir, "delphi-fallback.json") // or .yaml if you support YAML decoding

	secretsPtr, err := ReadFallbackJSON[map[string]string](path, log)
	if err != nil {
		log.Error("Could not load fallback secrets", zap.String("path", path), zap.Error(err))
		return nil, err
	}

	log.Info("📥 Fallback credentials loaded", zap.String("path", path))
	return *secretsPtr, nil
}

// ReadFallbackIntoJSON reads a fallback JSON file into the given output struct.
func ReadFallbackIntoJSON(path string, out any, log *zap.Logger) error {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Warn("Fallback file missing — skipping file read", zap.String("path", path), zap.Error(err))
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		log.Warn("unmarshal fallback JSON", zap.String("path", path), zap.Error(err))
		return err
	}
	return nil
}

func ListUnder(path string, log *zap.Logger) ([]string, error) {
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
