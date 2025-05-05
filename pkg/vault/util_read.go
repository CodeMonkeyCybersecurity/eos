package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoserr"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// Read tries to load a config from Vault; if unavailable, falls back to disk.
func Read(client *api.Client, name string, out any) error {
	if report, checked := Check(client, nil, ""); checked != nil && report.Initialized && !report.Sealed {
		if err := ReadFromVaultAt(context.Background(), shared.VaultMountKV, name, out); err == nil {
			return nil
		}
		zap.L().Warn("Vault read failed, falling back", zap.String("path", name))
	}
	return readJSONFile(DiskPath(name), out)
}

// ReadVault reads a Vault secret at a path into a typed struct.
func ReadVault[T any](path string) (*T, error) {
	return readAndUnmarshal[T]("secret", path)
}

// ReadFromVault wraps ReadFromVaultAt using the default mount.
func ReadFromVault(path string, out any) error {
	return ReadFromVaultAt(context.Background(), shared.VaultMountKV, path, out)
}

// ReadFromVaultAt reads and unmarshals a Vault KV v2 secret.
func ReadFromVaultAt(ctx context.Context, mount, path string, out any) error {
	client, err := GetVaultClient()
	if err != nil {
		return fmt.Errorf("get Vault client: %w", err)
	}
	secret, err := client.KVv2(mount).Get(ctx, path)
	if err != nil {
		return fmt.Errorf("vault API read %q: %w", path, err)
	}
	return unmarshalKVSecret(secret, path, out)
}

// SafeReadSecret reads a Vault secret, returning (nil, false) if failed.
func SafeReadSecret(path string) (*api.Secret, bool) {
	secret, err := readSecret(path)
	if err != nil || secret == nil {
		return nil, false
	}
	zap.L().Info("✅ Vault secret read", zap.String("path", path))
	return secret, true
}

// ReadSecret reads a Vault secret or returns eoserr.ErrSecretNotFound.
func ReadSecret(path string) (*api.Secret, error) {
	secret, err := readSecret(path)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, eoserr.ErrSecretNotFound
	}
	return secret, nil
}

// ReadFallbackJSON reads fallback JSON into any struct.
func ReadFallbackJSON[T any](path string, target *T) error {
	return readJSONFile(path, target)
}

// ReadVaultSecureData loads vault_init and userpass fallback files.
func ReadVaultSecureData(client *api.Client) (*api.InitResponse, shared.UserpassCreds, []string, string) {
	zap.L().Info("🔐 Starting secure Vault bootstrap sequence")
	if err := system.EnsureEosUser(true, false); err != nil {
		zap.L().Fatal("Failed to ensure eos system user", zap.Error(err))
	}

	initRes := mustReadTypedFile("vault_init", &api.InitResponse{})
	creds := mustReadTypedFile(shared.EosUserPassFallback, &shared.UserpassCreds{})

	if creds.Password == "" {
		zap.L().Fatal("Vault credentials password empty — aborting")
	}

	return initRes, *creds, crypto.HashStrings(initRes.KeysB64), crypto.HashString(initRes.RootToken)
}

// IsNotFoundError checks if the error is eoserr.ErrSecretNotFound.
func IsNotFoundError(err error) bool {
	return errors.Is(err, eoserr.ErrSecretNotFound)
}

// ListUnder lists Vault KV metadata keys under a path.
func ListUnder(path string) ([]string, error) {
	client, err := GetRootClient()
	if err != nil {
		return nil, fmt.Errorf("get Vault client: %w", err)
	}
	metaPath := fmt.Sprintf("%s/metadata/%s", shared.VaultMountKV, path)
	list, err := client.Logical().List(metaPath)
	if err != nil {
		return nil, fmt.Errorf("vault list failed: %w", err)
	}
	return extractKeys(list)
}

// ReadVaultInitResult loads the Vault init result from disk.
func ReadVaultInitResult() (*api.InitResponse, error) {
	var initRes api.InitResponse
	return &initRes, readJSONFile(shared.VaultInitPath, &initRes)
}

// InspectFromDisk reads and prints fallback test-data.
func InspectFromDisk() error {
	path := filepath.Join(shared.SecretsDir, shared.TestDataFilename)
	var out map[string]interface{}
	if err := readJSONFile(path, &out); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			zap.L().Warn("⚠️ Fallback test-data file not found", zap.String("path", path))
			return fmt.Errorf("no test-data found in Vault or disk")
		}
		zap.L().Error("Failed to read fallback test-data", zap.Error(err))
		return fmt.Errorf("disk fallback read failed: %w", err)
	}
	PrintData(out, "Disk", path)
	zap.L().Info("✅ Test-data read successfully from fallback")
	return nil
}

//
// INTERNAL HELPERS
//

func readSecret(path string) (*api.Secret, error) {
	client, err := GetVaultClient()
	if err != nil || client == nil {
		return nil, eoserr.NewExpectedError(fmt.Errorf("vault client not ready: %w", err))
	}
	return client.Logical().ReadWithContext(context.Background(), path)
}

func readAndUnmarshal[T any](mount, path string) (*T, error) {
	client, err := GetRootClient()
	if err != nil {
		return nil, fmt.Errorf("get root client: %w", err)
	}
	secret, err := client.KVv2(mount).Get(context.Background(), path)
	if err != nil {
		return nil, err
	}
	var result T
	return &result, unmarshalKVSecret(secret, path, &result)
}

func unmarshalKVSecret(secret *api.KVSecret, path string, out any) error {
	raw, ok := secret.Data["json"].(string)
	if !ok {
		return fmt.Errorf("missing or malformed 'json' at %q", path)
	}
	return json.Unmarshal([]byte(raw), out)
}

func readJSONFile(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func mustReadTypedFile[T any](path string, out *T) *T {
	if err := ReadFallbackJSON(path, out); err != nil {
		zap.L().Fatal("Failed to load fallback file", zap.String("path", path), zap.Error(err))
	}
	return out
}

func extractKeys(list *api.Secret) ([]string, error) {
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
