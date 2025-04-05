// pkg/vault/vault.go
package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
)

// LoadWithFallback attempts to load a configuration from the vault first, and if that fails,
// it falls back to loading from a local JSON file on disk.
// It uses the XDG_CONFIG_HOME environment variable to determine the path to the local config file.
// The function takes a name string to identify the configuration and an output variable to store the loaded data.
// It returns an error if both loading attempts fail.
// The function first constructs the vault path and the disk path for the configuration file.
// If the vault is available, it tries to read the configuration from the vault.
// If that fails, it attempts to read the configuration from the local disk.
// If both attempts fail, it returns an error indicating the failure to read the configuration.
// The function uses the vault package to read JSON data from the vault and the os package to read files from disk.
// It also uses the filepath package to construct file paths in a platform-independent way.
// The function is designed to be flexible and can be used in various contexts where configuration loading is needed.
// It is particularly useful in scenarios where configurations are stored in a vault for security reasons,
// but a fallback to local storage is also required.

// IsAvailable checks if Vault is accessible
func IsAvailable() bool {
	cmd := execute.ExecuteRaw("vault", "status")
	return cmd.Run() == nil
}

func LoadWithFallback(name string, out any) error {
	vaultPath := fmt.Sprintf("secret/eos/%s/config", name)
	diskPath := xdg.XDGConfigPath("eos", filepath.Join(name, "config.json"))

	// Ensure the directory exists
	// This is necessary to avoid errors when trying to read the file
	if err := os.MkdirAll(filepath.Dir(diskPath), 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if IsAvailable() {
		if err := ReadVaultJSON(vaultPath, out); err == nil {
			return nil
		}
	}

	b, err := os.ReadFile(diskPath)
	if err != nil {
		return fmt.Errorf("failed to read config from disk: %w", err)
	}
	return json.Unmarshal(b, out)
}

func SaveToVault(name string, in any) error {
	path := fmt.Sprintf("secret/eos/%s/config", name)
	return WriteVaultJSON(path, in)
}

// ReadJSON reads a JSON secret from Vault at the given path
func ReadVaultJSON(path string, out any) error {
	cmd := execute.ExecuteRaw("vault", "kv", "get", "-format=json", path)
	outBytes, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("vault read failed: %w", err)
	}

	var raw struct {
		Data struct {
			Data json.RawMessage `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(outBytes, &raw); err != nil {
		return fmt.Errorf("unmarshal vault json: %w", err)
	}
	return json.Unmarshal(raw.Data.Data, out)
}

// WriteJSON writes a JSON object to Vault at the given path
func WriteVaultJSON(path string, in any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}

	// Flatten JSON to key=value pairs
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
