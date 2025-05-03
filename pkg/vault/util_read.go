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

// ReadVault reads and decodes a secret struct from Vault.
func ReadVault[T any](path string) (*T, error) {
	client, err := GetPrivilegedVaultClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get privileged Vault client: %w", err)
	}

	kv := client.KVv2("secret")
	secret, err := kv.Get(context.Background(), path)
	if err != nil {
		zap.L().Warn("Vault KV read failed", zap.String("path", path), zap.Error(err))
		return nil, err
	}

	raw, ok := secret.Data["json"].(string)
	if !ok {
		zap.L().Error("Secret missing 'json' field or wrong format", zap.String("path", path))
		return nil, errors.New("missing or invalid 'json' field in Vault secret")
	}

	var result T
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		zap.L().Error("Failed to unmarshal Vault secret JSON", zap.String("path", path), zap.Error(err))
		return nil, fmt.Errorf("failed to unmarshal Vault secret: %w", err)
	}
	return &result, nil
}

// SafeReadSecret tries to read a Vault secret without returning hard errors.
// It logs problems as warnings and returns (nil, false) if anything goes wrong.
func SafeReadSecret(path string) (*api.Secret, bool) {
	client, err := GetVaultClient()
	if err != nil {
		zap.L().Warn("Vault client lookup failed", zap.Error(err))
		return nil, false
	}
	if client == nil {
		zap.L().Warn("Vault client is nil during SafeReadSecret", zap.String("path", path))
		return nil, false
	}

	secret, err := client.Logical().ReadWithContext(context.Background(), path)
	if err != nil {
		zap.L().Warn("Vault read failed in SafeReadSecret", zap.String("path", path), zap.Error(err))
		return nil, false
	}
	if secret == nil {
		zap.L().Warn("Vault secret not found in SafeReadSecret", zap.String("path", path))
		return nil, false
	}

	zap.L().Info("✅ Vault secret successfully read in SafeReadSecret", zap.String("path", path))
	return secret, true
}

// ReadSecret attempts to read a secret at a given path using the current Vault client.
func ReadSecret(path string) (*api.Secret, error) {
	client, err := GetVaultClient()
	if err != nil {
		zap.L().Warn("Vault client lookup failed", zap.Error(err))
		return nil, eoserr.NewExpectedError(fmt.Errorf("vault client lookup failed: %w", err))
	}
	if client == nil {
		zap.L().Warn("Vault client is nil during ReadSecret", zap.String("path", path))
		return nil, eoserr.NewExpectedError(fmt.Errorf("vault client is not ready"))
	}

	secret, err := client.Logical().ReadWithContext(context.Background(), path)
	if err != nil {
		zap.L().Warn("Vault read failed", zap.String("path", path), zap.Error(err))
		return nil, err
	}
	if secret == nil {
		return nil, eoserr.ErrSecretNotFound
	}
	return secret, nil
}

// IsNotFoundError returns true if the error indicates a missing secret.
func IsNotFoundError(err error) bool {
	return errors.Is(err, eoserr.ErrSecretNotFound)
}

// Read attempts to retrieve a config object from Vault. If Vault is unavailable or the read fails,
// it falls back to reading the config from disk (typically under ~/.config/eos/).
func Read(client *api.Client, name string, out any) error {
	report, checkedClient := Check(client, nil, "")
	if checkedClient == nil {
		zap.L().Error("Vault client returned from Check is nil")
		return fmt.Errorf("vault client is not ready")
	}
	if report.Initialized && !report.Sealed {
		err := ReadFromVaultAt(context.Background(), shared.VaultMountKV, name, out)
		if err == nil {
			return nil
		}
		zap.L().Warn("Vault read failed, falling back", zap.String("path", name), zap.Error(err))
	}
	return ReadFallback(DiskPath(name), out)
}

// ReadFromVault loads a struct from a Vault KV v2 path (default mount shared.VaultMountKV).
func ReadFromVault(path string, out interface{}) error {
	return ReadFromVaultAt(context.Background(), shared.VaultMountKV, path, out)
}

// ReadFromVaultAt loads a struct from a custom KV v2 mount path in Vault.
func ReadFromVaultAt(ctx context.Context, mount, path string, out interface{}) error {
	zap.L().Debug("Reading from Vault", zap.String("mount", mount), zap.String("path", path))
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
		return fmt.Errorf("missing or malformed 'json' field at path %q", path)
	}

	if err := json.Unmarshal([]byte(raw), out); err != nil {
		return fmt.Errorf("failed to unmarshal secret JSON at %q: %w", path, err)
	}

	zap.L().Info("✅ Vault secret successfully read", zap.String("mount", mount), zap.String("path", path))
	return nil
}

func ReadFallback(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		zap.L().Warn("Failed to read fallback file", zap.String("path", path), zap.Error(err))
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		zap.L().Warn("Failed to unmarshal fallback file", zap.String("path", path), zap.Error(err))
		return err
	}
	zap.L().Info("✅ Fallback config successfully loaded", zap.String("path", path))
	return nil
}

// ReadFallbackJSON reads a fallback JSON file into the provided output struct.
// Used when Vault is unavailable or secrets are stored locally.
func ReadFallbackJSON[T any](path string, target *T) error {
	data, err := os.ReadFile(path)
	if err != nil {
		zap.L().Warn("Failed to read fallback file", zap.String("path", path), zap.Error(err))
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		zap.L().Warn("Failed to unmarshal fallback file", zap.String("path", path), zap.Error(err))
		return err
	}
	zap.L().Info("✅ Fallback config successfully loaded", zap.String("path", path))
	return nil
}

// ReadVaultSecureData loads bootstrap Vault secrets (vault_init, userpass creds).
func ReadVaultSecureData(client *api.Client) (*api.InitResponse, shared.UserpassCreds, []string, string) {
	zap.L().Info("🔐 Starting secure Vault bootstrap sequence")

	if err := system.EnsureEosUser(true, false); err != nil {
		zap.L().Fatal("❌ Failed to ensure eos system user", zap.Error(err))
	}

	var initRes api.InitResponse
	vaultInitPath := DiskPath("vault_init")
	zap.L().Info("📄 Reading vault_init.json from fallback", zap.String("path", vaultInitPath))
	if err := ReadFallbackJSON(vaultInitPath, &initRes); err != nil {
		zap.L().Fatal("❌ Failed to read vault_init.json", zap.Error(err))
	}
	zap.L().Info("✅ Loaded vault_init.json", zap.Int("num_keys", len(initRes.KeysB64)))

	var creds shared.UserpassCreds
	zap.L().Info("📄 Reading eos userpass fallback file", zap.String("path", shared.EosUserVaultFallback))
	if err := ReadFallbackJSON(shared.EosUserVaultFallback, &creds); err != nil {
		zap.L().Fatal("❌ Failed to read vault_userpass.json", zap.Error(err))
	}

	if creds.Password == "" {
		zap.L().Fatal("❌ Loaded Vault credentials but password is empty — aborting.")
	}
	zap.L().Info("✅ Loaded eos Vault credentials")

	hashedKeys := crypto.HashStrings(initRes.KeysB64)
	hashedRoot := crypto.HashString(initRes.RootToken)

	zap.L().Info("🔑 Derived Vault hash summaries",
		zap.Int("key_count", len(hashedKeys)),
		zap.String("root_token_hash", hashedRoot),
	)

	zap.L().Info("🔒 Vault bootstrap sequence complete")
	return &initRes, creds, hashedKeys, hashedRoot
}

// ReadFallbackSecrets loads fallback secrets for Delphi (or other shared secrets).
func ReadFallbackSecrets() (map[string]string, error) {
	path := filepath.Join(shared.SecretsDir, "delphi-fallback.json")
	var secrets map[string]string
	if err := ReadFallbackJSON(path, &secrets); err != nil {
		zap.L().Error("Could not load fallback secrets", zap.String("path", path), zap.Error(err))
		return nil, err
	}
	zap.L().Info("📥 Fallback credentials loaded", zap.String("path", path))
	return secrets, nil
}

// ListUnder lists keys at a Vault KV metadata path (e.g., for KV v2 list operations).
// It uses the privileged Vault client and returns only the key names.
func ListUnder(path string) ([]string, error) {
	client, err := GetPrivilegedVaultClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get Vault client: %w", err)
	}

	metadataPath := fmt.Sprintf("%s/metadata/%s", shared.VaultMountKV, path)
	list, err := client.Logical().List(metadataPath)
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

// ReadVaultInitResult tries to load the saved Vault initialization result
func ReadVaultInitResult() (*api.InitResponse, error) {
	initRes := new(api.InitResponse)
	path := shared.VaultInitPath
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vault init result file: %w", err)
	}
	if err := json.Unmarshal(b, initRes); err != nil {
		return nil, fmt.Errorf("unmarshal vault init result: %w", err)
	}
	zap.L().Info("Vault init result loaded from disk", zap.String("path", path))
	return initRes, nil
}
