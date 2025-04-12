/* pkg/vault/reader */

package vault

import (
	"context"
	"encoding/json"
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
func ReadFromVault(path string, v interface{}) error {
	return ReadFromVaultAt(context.Background(), "secret", path, v)
}

// ReadFromVaultAt loads from a custom KV v2 mount.
func ReadFromVaultAt(ctx context.Context, mount, path string, v interface{}) error {
	client, err := GetVaultClient()
	if err != nil {
		return err
	}

	kv := client.KVv2(mount)
	secret, err := kv.Get(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to read from Vault: %w", err)
	}

	raw, ok := secret.Data["json"].(string)
	if !ok {
		return fmt.Errorf("missing or malformed 'json' field at path: %s", path)
	}

	if err := json.Unmarshal([]byte(raw), v); err != nil {
		return fmt.Errorf("failed to unmarshal Vault JSON: %w", err)
	}
	return nil
}

// Load loads from Vault or fallback to disk, based on availability.
func Read(client *api.Client, name string, v any) error {
	if IsVaultAvailable(client) {
		return readFromVault(client, name, v)
	}
	return readFallbackYAML(diskPath(name), v)
}

// readFromVault reads from logical path "secret/eos/<name>/config".
func readFromVault(client *api.Client, name string, out any) error {
	path := fmt.Sprintf("secret/eos/%s/config", name)
	return readVaultKV(client, path, out)
}

// readVaultKV reads directly from the logical API and parses Vault's KV v2 structure.
func readVaultKV(client *api.Client, path string, out any) error {
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("vault read failed: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return fmt.Errorf("no data found at %s", path)
	}

	data, ok := secret.Data["data"]
	if !ok {
		return fmt.Errorf("unexpected secret format: missing 'data'")
	}

	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal secret data: %w", err)
	}
	return json.Unmarshal(raw, out)
}

//
// === Fallback Read Helpers ===
//

func readFallbackYAML(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read fallback file: %w", err)
	}
	if err := yaml.Unmarshal(b, out); err != nil {
		return fmt.Errorf("unmarshal fallback YAML: %w", err)
	}
	return nil
}

func readFallbackSecrets() (map[string]string, error) {
	var secrets map[string]string
	err := readFallbackYAML(filepath.Clean(fallbackSecretsPath), &secrets)
	if err != nil {
		return nil, err
	}
	fmt.Printf("📥 Fallback credentials loaded from %s\n", fallbackSecretsPath)
	return secrets, nil
}

//
// === Secure Vault Loaders ===
//

func ReadVaultSecureData(client *api.Client) (*api.InitResponse, UserpassCreds, []string, string) {
	if err := eos.EnsureEosUser(); err != nil {
		log.Fatal("Failed to ensure eos system user", zap.Error(err))
	}

	fmt.Println("Secure Vault setup in progress...")
	fmt.Println("This process will revoke the root token and elevate admin privileges.")

	// Load vault-init metadata
	var initRes *api.InitResponse
	if err := Read(client, "vault-init", &initRes); err != nil {
		log.Fatal("Failed to load Vault init result", zap.Error(err))
	}

	var creds UserpassCreds
	if err := Read(client, "bootstrap/eos-user", &creds); err != nil {
		log.Fatal("Failed to load Vault userpass credentials", zap.Error(err))
	}

	if creds.Password == "" {
		log.Fatal("Parsed password is empty — aborting.")
	}

	hashedKeys := crypto.HashStrings(initRes.KeysB64)
	hashedRoot := crypto.HashString(initRes.RootToken)

	return initRes, creds, hashedKeys, hashedRoot
}
