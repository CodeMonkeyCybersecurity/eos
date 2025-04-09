package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v3"
)

//
// === Vault Write Helpers ===
//

// Save stores a struct in Vault or falls back to disk if unavailable.
func Save(client *api.Client, name string, data any) error {
	if IsVaultAvailable(client) {
		return saveToVault(name, data)
	}

	fmt.Println("⚠️ Vault not available — using fallback disk write.")
	return writeFallbackYAML(diskPath(name), data)
}

// saveToVault writes a structured secret to Vault using a standard namespaced path.
func saveToVault(name string, in any) error {
	return writeVaultJSON(vaultPath(name), in)
}

// SaveSecret writes a map directly to Vault.
func SaveSecret(client *api.Client, path string, data map[string]interface{}) error {
	_, err := client.Logical().Write(path, data)
	return err
}

// writeVaultJSON marshals `in` to JSON, flattens, and writes to Vault at the given path using the Vault CLI.
func writeVaultJSON(path string, in any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}

	var flat map[string]interface{}
	if err := json.Unmarshal(b, &flat); err != nil {
		return fmt.Errorf("flatten json: %w", err)
	}

	args := []string{"kv", "put", path}
	for k, v := range flat {
		args = append(args, fmt.Sprintf("%s=%v", k, v))
	}

	cmd := execute.ExecuteRaw("vault", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("vault write failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}

// write uses stdin to pass data to Vault's CLI as JSON.
// (Legacy - not used in Save. Kept for future flexibility.)
func write(path string, data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	cmd := exec.Command("vault", "kv", "put", path)
	cmd.Stdin = strings.NewReader(string(jsonData))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

//
// === Fallback (YAML) Helpers ===
//

// writeFallbackYAML writes any struct as YAML to a fallback path on disk.
func writeFallbackYAML(path string, data any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create fallback directory: %w", err)
	}

	b, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal fallback data: %w", err)
	}

	if err := os.WriteFile(path, b, 0600); err != nil {
		return fmt.Errorf("write fallback file: %w", err)
	}

	fmt.Printf("✅ Fallback data saved to %s\n", path)
	fmt.Println("💡 Run `eos vault sync` later to upload it to Vault.")
	return nil
}

// writeFallbackSecrets writes fallback secrets as YAML to a fixed secure path on disk.
func writeFallbackSecrets(secrets map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(fallbackSecretsPath), 0700); err != nil {
		return fmt.Errorf("create fallback directory: %w", err)
	}

	b, err := yaml.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("marshal fallback secrets: %w", err)
	}

	if err := os.WriteFile(fallbackSecretsPath, b, 0600); err != nil {
		return fmt.Errorf("write fallback file: %w", err)
	}

	fmt.Printf("✅ Fallback credentials saved to %s\n", fallbackSecretsPath)
	fmt.Println("💡 Run `eos vault sync` later to upload them to Vault.")
	return nil
}

// writeStruct is an alias for writeVaultJSON (kept for compatibility).
func writeStruct(path string, v interface{}) error {
	return writeVaultJSON(path, v)
}
