package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

//
// 🔐 Vault JSON Reads
//

func load(name string, out any) error {
	if isAvailable() {
		return readVaultJSON(vaultPath(name), out)
	}
	return readFallbackYAML(diskPath(name), out)
}

func read(path string) (map[string]interface{}, error) {
	output, err := exec.Command("vault", "kv", "get", "-format=json", path).Output()
	if err != nil {
		return nil, fmt.Errorf("vault command failed: %w", err)
	}
	var wrapper struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(output, &wrapper); err != nil {
		return nil, fmt.Errorf("unmarshal vault response: %w", err)
	}
	return wrapper.Data.Data, nil
}

func readVaultJSON(path string, out any) error {
	output, err := execute.ExecuteRaw("vault", "kv", "get", "-format=json", path).Output()
	if err != nil {
		return fmt.Errorf("vault read failed: %w", err)
	}

	var wrapper struct {
		Data struct {
			Data json.RawMessage `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(output, &wrapper); err != nil {
		return fmt.Errorf("unmarshal vault json: %w", err)
	}
	return json.Unmarshal(wrapper.Data.Data, out)
}

func loadFromVault(name string, out any) error {
	return readVaultJSON(fmt.Sprintf("secret/eos/%s/config", name), out)
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

func loadVaultSecureData() (initResult, UserpassCreds, []string, string) {
	if err := eos.EnsureEOSSystemUser(); err != nil {
		log.Fatal("Failed to ensure eos system user", zap.Error(err))
	}

	fmt.Println("Secure Vault setup in progress...")
	fmt.Println("This process will revoke the root token and elevate admin privileges.")

	// Load vault_init.json
	var initRes initResult
	if err := readFallbackYAML("vault_init.json", &initRes); err != nil {
		log.Fatal("Failed to load vault_init.json", zap.Error(err))
	}

	// Load Vault userpass credentials
	var creds UserpassCreds
	if err := readFallbackYAML("/var/lib/eos/secrets/vault-userpass.yaml", &creds); err != nil {
		log.Fatal("Failed to load Vault userpass credentials", zap.Error(err))
	}
	if creds.Password == "" {
		log.Fatal("Parsed password is empty — aborting.")
	}

	// Prehash values
	hashedKeys := crypto.HashStrings(initRes.UnsealKeysB64)
	hashedRoot := crypto.HashString(initRes.RootToken)

	return initRes, creds, hashedKeys, hashedRoot
}
