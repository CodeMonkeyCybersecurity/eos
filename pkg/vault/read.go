package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"gopkg.in/yaml.v3"
)

const fallbackSecretsPath = "/var/lib/eos/secrets/delphi-fallback.yaml"

// Load retrieves a struct from Vault or fallback if Vault is unavailable.
func load(name string, out any) error {
	if isAvailable() {
		return readVaultJSON(vaultPath(name), out)
	}
	return readFallbackYAML(diskPath(name), out)
}

//
// === Vault Read Helpers ===
//

// read fetches raw secret data from Vault and returns it as a flat map.
func read(path string) (map[string]interface{}, error) {
	cmd := exec.Command("vault", "kv", "get", "-format=json", path)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("vault command failed: %w", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal vault response: %w", err)
	}

	data := resp["data"].(map[string]interface{})
	return data["data"].(map[string]interface{}), nil
}

// readVaultJSON extracts a JSON-encoded secret from Vault and unmarshals it into `out`.
func readVaultJSON(path string, out any) error {
	cmd := execute.ExecuteRaw("vault", "kv", "get", "-format=json", path)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("vault read failed: %w", err)
	}

	var raw struct {
		Data struct {
			Data json.RawMessage `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(output, &raw); err != nil {
		return fmt.Errorf("unmarshal vault json: %w", err)
	}

	return json.Unmarshal(raw.Data.Data, out)
}

// readFallbackYAML reads YAML from the given fallback path into the provided struct.
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

// readStruct is an alias for reading JSON data into a provided struct.
func readStruct(path string, out any) error {
	return readVaultJSON(path, out)
}

// loadFromVault reads a secret from a default path: secret/eos/{{name}}/config
func loadFromVault(name string, out any) error {
	path := fmt.Sprintf("secret/eos/%s/config", name)
	return readVaultJSON(path, out)
}

//
// === Fallback Read Helpers ===
//

// readFallbackSecrets reads fallback YAML-based secrets from disk.
func readFallbackSecrets() (map[string]string, error) {
	b, err := os.ReadFile(filepath.Clean(fallbackSecretsPath))
	if err != nil {
		return nil, fmt.Errorf("read fallback file: %w", err)
	}

	var secrets map[string]string
	if err := yaml.Unmarshal(b, &secrets); err != nil {
		return nil, fmt.Errorf("unmarshal fallback secrets: %w", err)
	}

	fmt.Printf("📥 Fallback credentials loaded from %s\n", fallbackSecretsPath)
	return secrets, nil
}
