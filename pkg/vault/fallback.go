// pkg/vault/fallback.go
package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
)

// loadWithFallback attempts to load a config from Vault, falling back to local disk.
func loadWithFallback(name string, out any) error {
	vaultPath := fmt.Sprintf("secret/eos/%s/config", name)
	diskPath := xdg.XDGConfigPath("eos", filepath.Join(name, "config.json"))

	if err := os.MkdirAll(filepath.Dir(diskPath), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	if isAvailable() {
		if err := readVaultJSON(vaultPath, out); err == nil {
			return nil
		}
	}

	b, err := os.ReadFile(diskPath)
	if err != nil {
		return fmt.Errorf("read disk fallback: %w", err)
	}
	return json.Unmarshal(b, out)
}

// handleFallbackOrStore attempts to store secrets in Vault, or guides user fallback.
func handleFallbackOrStore(name string, secrets map[string]string) error {
	setVaultEnv()

	if isAvailable() {
		fmt.Println("🔐 Vault is available. Storing secrets securely.")
		return saveToVault(name, secrets)
	}

	switch promptFallbackChoice() {
	case "deploy":
		return deployAndStoreSecrets(name, secrets)
	case "disk":
		return writeFallbackSecrets(secrets)
	case "abort":
		return fmt.Errorf("vault unavailable, user aborted")
	default:
		return fmt.Errorf("unexpected choice")
	}
}

// promptFallbackChoice interacts with the user to determine fallback behavior.
func promptFallbackChoice() string {
	choice := interaction.PromptSelect("Vault not detected. What would you like to do?", []string{
		"Deploy local Vault now [recommended]",
		"Skip and save credentials to disk",
		"Abort",
	})

	switch choice {
	case "Deploy local Vault now [recommended]":
		return "deploy"
	case "Skip and save credentials to disk":
		return "disk"
	default:
		return "abort"
	}
}

// deployAndStoreSecrets automates Vault setup and stores secrets after confirmation.
func deployAndStoreSecrets(name string, secrets map[string]string) error {
	fmt.Println("🚀 Deploying Vault...")

	if err := execute.ExecuteAndLog("eos", "deploy", "vault"); err != nil && !strings.Contains(err.Error(), "already installed") {
		return fmt.Errorf("vault deploy failed: %w", err)
	}

	if err := execute.ExecuteAndLog("eos", "enable", "vault"); err != nil {
		fmt.Println("⚠️ Vault enable failed — manual unseal may be required.")
		return fmt.Errorf("vault enable failed: %w", err)
	}

	if err := execute.ExecuteAndLog("eos", "secure", "vault"); err != nil {
		return fmt.Errorf("vault secure failed: %w", err)
	}

	if !isVaultRunning() {
		return fmt.Errorf("vault does not appear to be running after setup. Try 'eos logs vault'")
	}

	fmt.Println("✅ Vault is running. Storing secrets...")
	return saveToVault(name, secrets)
}
