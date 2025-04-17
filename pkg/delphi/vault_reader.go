package delphi

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"go.uber.org/zap"
)

// GetDelphiAPICredsOrPrompt returns (username, password) either from Vault or prompt fallback
func GetDelphiAPICredsOrPrompt(log *zap.Logger) (string, string, error) {
	client, err := vault.GetPrivilegedVaultClient()
	if err != nil {
		log.Warn("Failed to initialize Vault client, falling back to prompt", zap.Error(err))
		return promptDelphiAPICreds(log)
	}

	secret, err := client.Logical().Read(VaultDelphiCreds)
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
	user := interaction.PromptInput("Enter the API username (e.g. wazuh-wui): ", "", log)
	pass, err := interaction.PromptPassword("Enter the API password", log)
	if err != nil {
		log.Error("Failed to read password", zap.Error(err))
		return "", "", err
	}

	log.Info("🔐 Saving entered API credentials to Vault")
	creds := &APICreds{
		Username: user,
		Password: pass,
	}
	err = vault.Write(nil, VaultDelphiCreds, creds, log)
	if err != nil {
		log.Warn("Failed to write Delphi API creds to Vault", zap.Error(err))
	}

	return user, pass, nil
}

/* ReadDelphiConfig loads Delphi config from Vault, then disk, then prompts interactively as a last resort. */
func ReadConfig(log *zap.Logger) (*Config, error) {
	var cfg Config

	// Try Vault first
	err := vault.Read(nil, VaultDelphiConfig, &cfg, log)
	if err == nil && cfg.FQDN != "" && cfg.APIUser != "" && cfg.APIPassword != "" {
		log.Info("✅ Loaded Delphi config from Vault")
		return &cfg, nil
	}

	log.Warn("⚠️  Delphi config not found or incomplete in Vault. Trying disk fallback...")

	// Try disk fallback
	diskPath := xdg.XDGConfigPath("eos", "delphi.json")
	data, err := os.ReadFile(diskPath)
	if err == nil {
		if err := json.Unmarshal(data, &cfg); err == nil && cfg.FQDN != "" {
			log.Info("✅ Loaded Delphi config from disk", zap.String("path", diskPath))
			return &cfg, nil
		}
		log.Warn("❌ Failed to parse disk config or it was incomplete", zap.Error(err))
	}

	pw, err := interaction.PromptPassword("Enter the API password", log)
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	cfg.APIPassword = pw

	// Optionally save to disk
	if err := WriteConfig(&cfg, log); err != nil {
		log.Warn("⚠️  Failed to write disk config fallback", zap.Error(err))
	}

	// Attempt to write back to Vault
	if err := vault.Write(nil, VaultDelphiConfig, &cfg, log); err != nil {
		log.Warn("⚠️  Failed to save config to Vault", zap.Error(err))
	} else {
		log.Info("✅ Delphi config saved to Vault")
	}

	return &cfg, nil
}

func ReadCreds(log *zap.Logger) (*APICreds, error) {
	cfg, err := ReadConfig(log)
	if err != nil {
		return nil, err
	}
	return &APICreds{
		Username: cfg.APIUser,
		Password: cfg.APIPassword,
	}, nil
}
