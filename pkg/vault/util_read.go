package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Read tries to load a config from Vault; if unavailable, falls back to disk.
func Read(rc *eos_io.RuntimeContext, client *api.Client, name string, out any) error {
	if report, checked := Check(rc, client, nil, ""); checked != nil && report.Initialized && !report.Sealed {
		if err := ReadFromVaultAt(rc, shared.VaultMountKV, name, out); err == nil {
			return nil
		}
		otelzap.Ctx(rc.Ctx).Warn("Vault read failed, falling back", zap.String("path", name))
	}
	return readJSONFile(DiskPath(rc, name), out)
}

// ReadVault reads a Vault secret at a path into a typed struct.
func ReadVault[T any](rc *eos_io.RuntimeContext, path string) (*T, error) {
	return readAndUnmarshal[T](rc, "secret", path)
}

// ReadFromVault wraps ReadFromVaultAt using the default mount.
func ReadFromVault(rc *eos_io.RuntimeContext, path string, out any) error {
	return ReadFromVaultAt(rc, shared.VaultMountKV, path, out)
}

// ReadFromVaultAt reads and unmarshals a Vault KV v2 secret.
func ReadFromVaultAt(rc *eos_io.RuntimeContext, mount, path string, out any) error {
	client, err := GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("get Vault client: %w", err)
	}
	secret, err := client.KVv2(mount).Get(rc.Ctx, path)
	if err != nil {
		return fmt.Errorf("vault API read %q: %w", path, err)
	}
	return unmarshalKVSecret(secret, path, out)
}

// SafeReadSecret reads a Vault secret, returning (nil, false) if failed.
func SafeReadSecret(rc *eos_io.RuntimeContext, path string) (*api.Secret, bool) {
	secret, err := readSecret(rc, path)
	if err != nil || secret == nil {
		return nil, false
	}
	otelzap.Ctx(rc.Ctx).Info("✅ Vault secret read", zap.String("path", path))
	return secret, true
}

// ReadSecret reads a Vault secret or returns eos_err.ErrSecretNotFound.
func ReadSecret(rc *eos_io.RuntimeContext, path string) (*api.Secret, error) {
	secret, err := readSecret(rc, path)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, eos_err.ErrSecretNotFound
	}
	return secret, nil
}

// ReadFallbackJSON reads fallback JSON into any struct.
func ReadFallbackJSON[T any](path string, target *T) error {
	return readJSONFile(path, target)
}

// ReadVaultSecureData loads vault_init and userpass fallback files.
func ReadVaultSecureData(rc *eos_io.RuntimeContext, client *api.Client) (*api.InitResponse, shared.UserpassCreds, []string, string) {
	otelzap.Ctx(rc.Ctx).Info("🔐 Starting secure Vault bootstrap sequence")
	if err := eos_unix.EnsureEosUser(rc.Ctx, true, false); err != nil {
		otelzap.Ctx(rc.Ctx).Fatal("Failed to ensure eos system user", zap.Error(err))
	}

	initRes := mustReadTypedFile(rc, "vault_init", &api.InitResponse{})
	creds := mustReadTypedFile(rc, shared.EosUserPassFallback, &shared.UserpassCreds{})

	if creds.Password == "" {
		otelzap.Ctx(rc.Ctx).Fatal("Vault credentials password empty — aborting")
	}

	return initRes, *creds, crypto.HashStrings(initRes.KeysB64), crypto.HashString(initRes.RootToken)
}

// IsNotFoundError checks if the error is eos_err.ErrSecretNotFound.
func IsNotFoundError(err error) bool {
	return errors.Is(err, eos_err.ErrSecretNotFound)
}

// ListUnder lists Vault KV metadata keys under a path.
func ListUnder(rc *eos_io.RuntimeContext, path string) ([]string, error) {
	client, err := GetRootClient(rc)
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
func InspectFromDisk(rc *eos_io.RuntimeContext) error {
	path := filepath.Join(shared.SecretsDir, shared.TestDataFilename)
	var out map[string]interface{}
	if err := readJSONFile(path, &out); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			otelzap.Ctx(rc.Ctx).Warn("⚠️ Fallback test-data file not found", zap.String("path", path))
			return fmt.Errorf("no test-data found in Vault or disk")
		}
		otelzap.Ctx(rc.Ctx).Error("Failed to read fallback test-data", zap.Error(err))
		return fmt.Errorf("disk fallback read failed: %w", err)
	}
	PrintData(rc.Ctx, out, "Disk", path)
	otelzap.Ctx(rc.Ctx).Info("✅ Test-data read successfully from fallback")
	return nil
}

//
// INTERNAL HELPERS
//

func readSecret(rc *eos_io.RuntimeContext, path string) (*api.Secret, error) {
	client, err := GetVaultClient(rc)
	if err != nil || client == nil {
		return nil, eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("vault client not ready: %w", err))
	}
	return client.Logical().ReadWithContext(context.Background(), path)
}

func readAndUnmarshal[T any](rc *eos_io.RuntimeContext, mount, path string) (*T, error) {
	client, err := GetRootClient(rc)
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

func mustReadTypedFile[T any](rc *eos_io.RuntimeContext, path string, out *T) *T {
	if err := ReadFallbackJSON(path, out); err != nil {
		otelzap.Ctx(rc.Ctx).Fatal("Failed to load fallback file", zap.String("path", path), zap.Error(err))
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
