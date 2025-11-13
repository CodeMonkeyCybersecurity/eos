package wazuh

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetWazuhAPICredsOrPrompt returns (username, password) either from Vault or prompt fallback
func GetWazuhAPICredsOrPrompt(rc *eos_io.RuntimeContext) (string, string, error) {
	client, err := vault.GetRootClient(rc)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Failed to initialize Vault client, falling back to prompt", zap.Error(err))
		return promptWazuhAPICreds(rc)
	}

	secret, err := client.Logical().Read(VaultWazuhCreds)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Vault read error", zap.Error(err))
		return promptWazuhAPICreds(rc)
	}

	if secret == nil || secret.Data == nil {
		otelzap.Ctx(rc.Ctx).Warn("Vault secret is nil, falling back to prompt")
		return promptWazuhAPICreds(rc)
	}

	// Vault KV v2 requires `.Data["data"]`
	raw, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		otelzap.Ctx(rc.Ctx).Warn("Vault secret structure malformed", zap.Any("data", secret.Data))
		return promptWazuhAPICreds(rc)
	}

	user := fmt.Sprint(raw["username"])
	pass := fmt.Sprint(raw["password"])
	if user == "" || pass == "" {
		otelzap.Ctx(rc.Ctx).Warn("Vault secret fields missing", zap.Any("data", raw))
		return promptWazuhAPICreds(rc)
	}

	otelzap.Ctx(rc.Ctx).Info(" Retrieved Wazuh API credentials from Vault")
	return user, pass, nil
}

// promptWazuhAPICreds prompts interactively, then optionally writes back to Vault
func promptWazuhAPICreds(rc *eos_io.RuntimeContext) (string, string, error) {
	user := interaction.PromptInput(rc.Ctx, "Enter the API username (e.g. wazuh-wui): ", "")
	pass, err := crypto.PromptPassword(rc, "Enter the API password")
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to read password", zap.Error(err))
		return "", "", err
	}

	otelzap.Ctx(rc.Ctx).Info(" Saving entered API credentials to Vault")
	creds := &APICreds{
		Username: user,
		Password: pass,
	}
	err = vault.Write(rc, nil, VaultWazuhCreds, creds)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Failed to write Wazuh API creds to Vault", zap.Error(err))
	}

	return user, pass, nil
}

/* ReadWazuhConfig loads Wazuh config from Vault, then disk, then prompts interactively as a last resort. */
func ReadConfig(rc *eos_io.RuntimeContext) (*Config, error) {
	var cfg Config

	// Try Vault first
	err := vault.Read(rc, nil, VaultWazuhConfig, &cfg)
	if err == nil && cfg.FQDN != "" && cfg.APIUser != "" && cfg.APIPassword != "" {
		otelzap.Ctx(rc.Ctx).Info(" Loaded Wazuh config from Vault")
		return &cfg, nil
	}

	otelzap.Ctx(rc.Ctx).Warn(" Wazuh config not found or incomplete in Vault. Trying disk fallback...")

	// Try disk fallback
	diskPath := xdg.XDGConfigPath(shared.EosID, "wazuh.json")
	data, err := os.ReadFile(diskPath)
	if err == nil {
		if err := json.Unmarshal(data, &cfg); err == nil && cfg.FQDN != "" {
			otelzap.Ctx(rc.Ctx).Info(" Loaded Wazuh config from disk", zap.String("path", diskPath))
			return &cfg, nil
		}
		otelzap.Ctx(rc.Ctx).Warn(" Failed to parse disk config or it was incomplete", zap.Error(err))
	}

	pw, err := crypto.PromptPassword(rc, "Enter the API password")
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	cfg.APIPassword = pw

	// Optionally save to disk
	if err := WriteConfig(rc, &cfg); err != nil {
		otelzap.Ctx(rc.Ctx).Warn(" Failed to write disk config fallback", zap.Error(err))
	}

	// Attempt to write back to Vault
	if err := vault.Write(rc, nil, VaultWazuhConfig, &cfg); err != nil {
		otelzap.Ctx(rc.Ctx).Warn(" Failed to save config to Vault", zap.Error(err))
	} else {
		otelzap.Ctx(rc.Ctx).Info(" Wazuh config saved to Vault")
	}

	return &cfg, nil
}

func ReadCreds(rc *eos_io.RuntimeContext) (*APICreds, error) {
	cfg, err := ReadConfig(rc)
	if err != nil {
		return nil, err
	}
	return &APICreds{
		Username: cfg.APIUser,
		Password: cfg.APIPassword,
	}, nil
}
