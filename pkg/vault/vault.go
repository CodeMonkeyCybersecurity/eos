// pkg/vault/vault.go
package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
)

// IsAvailable checks if Vault is accessible
func IsAvailable() bool {
	cmd := execute.ExecuteRaw("vault", "status")
	return cmd.Run() == nil
}

// LoadWithFallback attempts to load a JSON secret from Vault, falling back to a local file if Vault is unavailable
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

// SaveToVault saves a JSON secret to Vault at the given path
func SaveToVault(name string, in any) error {
	path := fmt.Sprintf("secret/eos/%s/config", name)
	return WriteVaultJSON(path, in)
}

// HandleFallbackOrStore checks if Vault is installed and running, and either stores secrets in Vault or prompts the user for action
func HandleFallbackOrStore() error {
	SetVaultEnv()

	if IsVaultInstalled() && IsVaultRunning() {
		fmt.Println("Vault detected and healthy. Proceeding to store secrets securely.")
		// TODO: Replace this dummy struct with real secrets
		dummySecrets := map[string]string{
			"wazuh":     "new-wazuh-pass",
			"wazuh-wui": "new-wazuh-wui-pass",
		}
		if err := SaveToVault("delphi", dummySecrets); err != nil {
			return fmt.Errorf("failed to store secrets in Vault: %w", err)
		}
		return nil
	}

	choice := interaction.PromptSelect("Vault not detected. What would you like to do?", []string{
		"Deploy local Vault now [recommended]",
		"Skip and save credentials to disk",
		"Abort",
	})

	switch choice {
	case "Deploy local Vault now [recommended]":
		fmt.Println("Launching vault deployment sequence...")
		// TODO: Call `eos deploy vault` or invoke the logic directly
	case "Skip and save credentials to disk":
		fmt.Println("Saving credentials to fallback location: /var/lib/eos/secrets/delphi-fallback.yaml")
		if err := writeFallbackSecrets(); err != nil {
			return fmt.Errorf("failed to write fallback secrets: %w", err)
		}
	case "Abort":
		return fmt.Errorf("vault not available, user aborted")
	}

	return nil
}
