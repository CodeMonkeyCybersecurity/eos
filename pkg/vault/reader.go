package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// Read attempts to retrieve a config object from Vault. If Vault is unavailable or the read fails,
// it falls back to reading the config from disk (typically under ~/.config/eos/).
func Read(client *api.Client, name string, out any, log *zap.Logger) error {
	report, checkedClient := Check(client, log, nil, "")
	if checkedClient == nil {
		log.Error("Vault client returned from Check is nil")
		return fmt.Errorf("vault client is not ready")
	}
	if checkedClient == nil {
		return fmt.Errorf("vault client is not ready")
	}
	if report.Initialized && !report.Sealed {
		err := ReadFromVaultAt(context.Background(), shared.VaultMountKV, name, out, log)
		if err == nil {
			return nil
		}
		log.Warn("Vault read failed, falling back", zap.String("path", name), zap.Error(err))
	}
	return ReadFallback(DiskPath(name, log), out, log)
}

// ReadFromVault loads a struct from a Vault KV v2 path (default mount shared.VaultMountKV).
func ReadFromVault(path string, out interface{}, log *zap.Logger) error {
	return ReadFromVaultAt(context.Background(), shared.VaultMountKV, path, out, log)
}

// ReadFromVaultAt loads a struct from a custom KV v2 mount path in Vault.
func ReadFromVaultAt(ctx context.Context, mount, path string, out interface{}, log *zap.Logger) error {
	log.Debug("Reading from Vault", zap.String("mount", mount), zap.String("path", path))
	client, err := GetVaultClient(log)
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

	log.Info("✅ Vault secret successfully read", zap.String("mount", mount), zap.String("path", path))
	return nil
}

func ReadFallback(path string, out any, log *zap.Logger) error {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Warn("Failed to read fallback file", zap.String("path", path), zap.Error(err))
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		log.Warn("Failed to unmarshal fallback file", zap.String("path", path), zap.Error(err))
		return err
	}
	log.Info("✅ Fallback config successfully loaded", zap.String("path", path))
	return nil
}

// ReadFallbackJSON reads a fallback JSON file into the provided output struct.
// Used when Vault is unavailable or secrets are stored locally.
func ReadFallbackJSON[T any](path string, target *T, log *zap.Logger) error {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Warn("Failed to read fallback file", zap.String("path", path), zap.Error(err))
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		log.Warn("Failed to unmarshal fallback file", zap.String("path", path), zap.Error(err))
		return err
	}
	log.Info("✅ Fallback config successfully loaded", zap.String("path", path))
	return nil
}

// ReadVaultSecureData loads bootstrap Vault secrets (vault_init, userpass creds).
func ReadVaultSecureData(client *api.Client, log *zap.Logger) (*api.InitResponse, UserpassCreds, []string, string) {
	log.Info("🔐 Starting secure Vault bootstrap sequence")

	if err := system.EnsureEosUser(true, false, log); err != nil {
		log.Fatal("❌ Failed to ensure eos system user", zap.Error(err))
	}

	var initRes api.InitResponse
	vaultInitPath := DiskPath("vault_init", log)
	log.Info("📄 Reading vault_init.json from fallback", zap.String("path", vaultInitPath))
	if err := ReadFallbackJSON(vaultInitPath, &initRes, log); err != nil {
		log.Fatal("❌ Failed to read vault_init.json", zap.Error(err))
	}
	log.Info("✅ Loaded vault_init.json", zap.Int("num_keys", len(initRes.KeysB64)))

	var creds UserpassCreds
	log.Info("📄 Reading eos userpass fallback file", zap.String("path", shared.EosUserVaultFallback))
	if err := ReadFallbackJSON(shared.EosUserVaultFallback, &creds, log); err != nil {
		log.Fatal("❌ Failed to read vault_userpass.json", zap.Error(err))
	}

	if creds.Password == "" {
		log.Fatal("❌ Loaded Vault credentials but password is empty — aborting.")
	}
	log.Info("✅ Loaded eos Vault credentials")

	hashedKeys := crypto.HashStrings(initRes.KeysB64)
	hashedRoot := crypto.HashString(initRes.RootToken)

	log.Info("🔑 Derived Vault hash summaries",
		zap.Int("key_count", len(hashedKeys)),
		zap.String("root_token_hash", hashedRoot),
	)

	log.Info("🔒 Vault bootstrap sequence complete")
	return &initRes, creds, hashedKeys, hashedRoot
}

// ReadFallbackSecrets loads fallback secrets for Delphi (or other shared secrets).
func ReadFallbackSecrets(log *zap.Logger) (map[string]string, error) {
	path := filepath.Join(shared.SecretsDir, "delphi-fallback.json")
	var secrets map[string]string
	if err := ReadFallbackJSON(path, &secrets, log); err != nil {
		log.Error("Could not load fallback secrets", zap.String("path", path), zap.Error(err))
		return nil, err
	}
	log.Info("📥 Fallback credentials loaded", zap.String("path", path))
	return secrets, nil
}

// ListUnder lists keys at a Vault KV metadata path (e.g., for KV v2 list operations).
// It uses the privileged Vault client and returns only the key names.
func ListUnder(path string, log *zap.Logger) ([]string, error) {
	client, err := GetPrivilegedVaultClient(log)
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
