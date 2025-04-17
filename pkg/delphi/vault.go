package delphi

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"go.uber.org/zap"
)

// GetDelphiAPICredsOrPrompt returns (username, password) either from Vault or prompt fallback
func GetDelphiAPICredsOrPrompt(log *zap.Logger) (string, string, error) {
	client, err := vault.GetPrivilegedVaultClient()
	if err != nil {
		log.Warn("Failed to initialize Vault client, falling back to prompt", zap.Error(err))
		return promptDelphiAPICreds(log)
	}

	secret, err := client.Logical().Read(APICreds)
	if err != nil {
		log.Warn("Vault read error", zap.Error(err))
		return promptDelphiAPICreds(log)
	}

	if secret == nil || secret.Data == nil {
		log.Warn("Vault secret is nil, falling back to prompt")
		return promptDelphiAPICreds(log)
	}

	// Vault KV v2 requires `.Data["data"]`
	raw, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		log.Warn("Vault secret structure malformed", zap.Any("data", secret.Data))
		return promptDelphiAPICreds(log)
	}

	user := fmt.Sprint(raw["username"])
	pass := fmt.Sprint(raw["password"])
	if user == "" || pass == "" {
		log.Warn("Vault secret fields missing", zap.Any("data", raw))
		return promptDelphiAPICreds(log)
	}

	log.Info("✅ Retrieved Delphi API credentials from Vault")
	return user, pass, nil
}

// promptDelphiAPICreds prompts interactively, then optionally writes back to Vault
func promptDelphiAPICreds(log *zap.Logger) (string, string, error) {
	user := interaction.PromptInput("Enter the API username (e.g. wazuh-wui): ", "")
	pass, err := interaction.PromptPassword("Enter the API password")
	if err != nil {
		log.Error("Failed to read password", zap.Error(err))
		return "", "", err
	}

	log.Info("🔐 Saving entered API credentials to Vault")
	err = vault.Write(nil, APICreds, map[string]interface{}{
		"username": user,
		"password": pass,
	}, log)
	if err != nil {
		log.Warn("Failed to write Delphi API creds to Vault", zap.Error(err))
	}

	return user, pass, nil
}