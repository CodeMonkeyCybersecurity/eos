package vault

import (
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
// 🔐 Vault JSON Reads
//

func load(client *api.Client, name string, out any) error {
	if isAvailable() {
		return loadFromVault(client, name, out)
	}
	return readFallbackYAML(diskPath(name), out)
}

func readVaultKV(client *api.Client, path string, out any) error {
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("vault read failed: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return fmt.Errorf("no data found at %s", path)
	}

	// Vault KV v2 nesting
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

func loadFromVault(client *api.Client, name string, out any) error {
	path := fmt.Sprintf("secret/eos/%s/config", name)
	return readVaultKV(client, path, out)
}

//
// 🛟 Fallback YAML Reads
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
// 🔐 Secure Vault Loader
//

func loadVaultSecureData(client *api.Client) (*api.InitResponse, UserpassCreds, []string, string) {
	if err := eos.EnsureEosUser(); err != nil {
		log.Fatal("Failed to ensure eos system user", zap.Error(err))
	}

	fmt.Println("Secure Vault setup in progress...")
	fmt.Println("This process will revoke the root token and elevate admin privileges.")

	// Load vault_init.json
	var initRes *api.InitResponse
	if err := load(client, "vault-init", &initRes); err != nil {
		log.Fatal("Failed to load Vault init result", zap.Error(err))
	}

	// Load Vault userpass credentials
	var creds UserpassCreds
	if err := load(client, "bootstrap/eos-user", &creds); err != nil {
		log.Fatal("Failed to load Vault userpass credentials", zap.Error(err))
	}

	if creds.Password == "" {
		log.Fatal("Parsed password is empty — aborting.")
	}

	// Prehash values
	hashedKeys := crypto.HashStrings(initRes.KeysB64)
	hashedRoot := crypto.HashString(initRes.RootToken)

	return initRes, creds, hashedKeys, hashedRoot
}
