package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

//
// === Vault Read Helpers ===
//

// ReadFromVault loads a struct from a Vault KV v2 path (default mount "secret").
func ReadFromVault(path string, out interface{}) error {
	return ReadFromVaultAt(context.Background(), "secret", path, out)
}

// ReadFromVaultAt loads a struct from a custom KV v2 mount.
func ReadFromVaultAt(ctx context.Context, mount, path string, out interface{}) error {
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

// Read loads a namespaced config from Vault, or falls back to YAML if unavailable.
func Read(client *api.Client, name string, out any) error {
	if IsVaultAvailable(client) {
		err := readFromVault(client, name, out)
		if err == nil {
			return nil
		}
		fmt.Printf("⚠️  Vault read failed for %q: %v\n", name, err)
		fmt.Println("💡 Falling back to local config...")
	}
	return readFallbackYAML(diskPath(name), out)
}

// readFromVault reads from logical path "secret/eos/<name>/config".
func readFromVault(client *api.Client, name string, out any) error {
	path := fmt.Sprintf("secret/eos/%s/config", name)
	return readVaultKV(client, path, out)
}

// readVaultKV reads raw KV v2 data from Vault and unmarshals into out.
func readVaultKV(client *api.Client, path string, out any) error {
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("vault read failed for path %q: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return fmt.Errorf("no data found at %q", path)
	}

	data, ok := secret.Data["data"]
	if !ok {
		return errors.New("vault KV response missing 'data' key")
	}

	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to re-marshal Vault data: %w", err)
	}
	return json.Unmarshal(raw, out)
}

//
// === Fallback Read Helpers ===
//

func readFallbackYAML(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read fallback file %q: %w", path, err)
	}
	if err := yaml.Unmarshal(b, out); err != nil {
		return fmt.Errorf("failed to parse fallback YAML at %q: %w", path, err)
	}
	return nil
}

func readFallbackSecrets() (map[string]string, error) {
	var secrets map[string]string
	err := readFallbackYAML(filepath.Clean(fallbackSecretsPath), &secrets)
	if err != nil {
		return nil, fmt.Errorf("could not load fallback secrets: %w", err)
	}
	fmt.Printf("📥 Fallback credentials loaded from %s\n", fallbackSecretsPath)
	return secrets, nil
}

//
// === Secure Vault Loaders ===
//

// ReadVaultSecureData loads bootstrap Vault secrets (vault-init, userpass creds).
func ReadVaultSecureData(client *api.Client) (*api.InitResponse, UserpassCreds, []string, string) {
	if err := eos.EnsureEosUser(); err != nil {
		log.Fatal("❌ Failed to ensure eos system user", zap.Error(err))
	}

	fmt.Println("🔐 Secure Vault setup in progress...")
	fmt.Println("This will revoke the root token and promote the eos admin user.")

	var initRes *api.InitResponse
	if err := Read(client, "vault-init", &initRes); err != nil {
		log.Fatal("❌ Failed to load vault-init metadata", zap.Error(err))
	}

	var creds UserpassCreds
	if err := Read(client, "bootstrap/eos-user", &creds); err != nil {
		log.Fatal("❌ Failed to load eos userpass credentials", zap.Error(err))
	}

	if creds.Password == "" {
		log.Fatal("❌ Loaded Vault credentials but password is empty — aborting.")
	}

	hashedKeys := crypto.HashStrings(initRes.KeysB64)
	hashedRoot := crypto.HashString(initRes.RootToken)

	return initRes, creds, hashedKeys, hashedRoot
}
