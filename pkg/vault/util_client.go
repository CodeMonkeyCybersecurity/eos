/* pkg/vault/client.go */

package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// EnsureVaultClient guarantees a working Vault client is globally cached and returned.
func EnsureVaultClient(log *zap.Logger) (*api.Client, error) {
	if client, err := GetVaultClient(log); err == nil && client != nil {
		if validated, _ := validateClient(client, log); validated != nil {
			SetVaultClient(validated, log)
			return validated, nil
		}
	}

	if client, err := tryClientFromEnv(log); err == nil {
		if validated, _ := validateClient(client, log); validated != nil {
			SetVaultClient(validated, log)
			return validated, nil
		}
		log.Warn("⚠️ Vault client from env is unhealthy")
	}

	if client, err := tryPrivilegedClient(log); err == nil {
		if validated, _ := validateClient(client, log); validated != nil {
			SetVaultClient(validated, log)
			return validated, nil
		}
		log.Warn("⚠️ Privileged client is unhealthy")
	} else {
		log.Error("❌ Failed to create privileged Vault client", zap.Error(err))
	}

	log.Error("❌ Could not initialize a working Vault client")
	return nil, fmt.Errorf("no valid Vault client could be established")
}

// tryClientFromEnv creates a Vault client from environment variables.
func tryClientFromEnv(log *zap.Logger) (*api.Client, error) {
	log.Info("🔐 Attempting to initialize Vault client from environment (VAULT_TOKEN)...")
	client, err := NewClient(log)
	if err != nil {
		return nil, fmt.Errorf("env client creation failed: %w", err)
	}
	log.Info("✅ Vault client created from environment")
	return client, nil
}

// tryPrivilegedClient attempts to load Vault client using Vault Agent or vault_init.json.
func tryPrivilegedClient(log *zap.Logger) (*api.Client, error) {
	log.Info("🔐 Falling back to Vault Agent AppRole authentication...")
	client, err := EnsurePrivilegedVaultClient(log)
	if err != nil {
		return nil, fmt.Errorf("privileged client setup failed: %w", err)
	}
	log.Info("✅ Vault client initialized via privileged agent")
	return client, nil
}

// validateClient runs diagnostics and returns the final usable client (if valid).
func validateClient(client *api.Client, log *zap.Logger) (*api.Client, *shared.CheckReport) {
	report, checkedClient := Check(client, log, nil, "")
	if checkedClient != nil {
		client = checkedClient
	}
	if report == nil {
		log.Warn("⚠️ Vault check returned nil — skipping further setup")
		return nil, nil
	}
	for _, note := range report.Notes {
		log.Warn("⚠️ Vault diagnostic note", zap.String("note", note))
	}
	return client, report
}

// NewClient returns a Vault client that
//   - uses EnsureVaultEnv() for the endpoint
//   - trusts /opt/vault/tls/tls.crt unless the user already provided a CA.
func NewClient(log *zap.Logger) (*api.Client, error) {
	addr, _ := EnsureVaultEnv(log)

	cfg := api.DefaultConfig()
	cfg.Address = addr

	// 1) merge VAULT_* environment variables (incl. VAULT_CACERT)
	if err := cfg.ReadEnvironment(); err != nil {
		log.Warn("⚠️ could not read Vault env config", zap.Error(err))
	}

	// 2) if the caller did NOT provide a CA path, inject our local one
	if os.Getenv("VAULT_CACERT") == "" {
		if err := cfg.ConfigureTLS(&api.TLSConfig{
			CACert: "/opt/vault/tls/tls.crt",
		}); err != nil {
			return nil, fmt.Errorf("tls‑config: %w", err)
		}
	}

	cli, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("new‑client: %w", err)
	}

	// 3) propagate VAULT_TOKEN if it exists
	if tok := os.Getenv("VAULT_TOKEN"); tok != "" {
		cli.SetToken(tok)
	}

	return cli, nil
}

func SetVaultClient(client *api.Client, log *zap.Logger) {
	log.Debug("📦 Vault client cached globally")
	shared.VaultClient = client
}

func GetVaultClient(log *zap.Logger) (*api.Client, error) {
	if shared.VaultClient == nil {
		log.Debug("❌ Vault client requested but not initialized")
		return nil, fmt.Errorf("vault client is not initialized; call SetVaultClient first")
	}
	log.Debug("📦 Returning cached Vault client")
	return shared.VaultClient, nil
}

// EnsurePrivilegedVaultClient tries to get a working Vault client
// 1. Prefer Vault Agent sink token
// 2. Fall back to vault_init.json root token from SecretsDir
func EnsurePrivilegedVaultClient(log *zap.Logger) (*api.Client, error) {
	log.Debug("🔐 Attempting privileged Vault client setup")

	// 1. Try to read Vault Agent token first
	token, err := readTokenFromSink(shared.VaultAgentTokenPath)
	if err != nil {
		log.Warn("⚠️ Vault Agent token not found, falling back to vault_init.json", zap.Error(err))

		// 2. Fallback: read root token from vault_init.json
		var initRes shared.VaultInitResponse
		vaultInitPath := filepath.Join(shared.SecretsDir, "vault_init.json")
		raw, err := os.ReadFile(vaultInitPath)
		if err != nil {
			log.Error("❌ Failed to read vault_init.json fallback", zap.String("path", vaultInitPath), zap.Error(err))
			return nil, fmt.Errorf("failed to read vault_init.json: %w", err)
		}
		if err := json.Unmarshal(raw, &initRes); err != nil {
			log.Error("❌ Failed to unmarshal vault_init.json", zap.Error(err))
			return nil, fmt.Errorf("failed to unmarshal vault_init.json: %w", err)
		}
		token = initRes.RootToken
		if token == "" {
			return nil, fmt.Errorf("vault_init.json contains empty root token")
		}
	}

	client, err := NewClient(log)
	if err != nil {
		log.Error("❌ Failed to create Vault client", zap.Error(err))
		return nil, err
	}

	client.SetToken(token)
	log.Info("✅ Privileged Vault client ready")
	return client, nil
}
