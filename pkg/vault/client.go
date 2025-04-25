/* pkg/vault/client.go */

package vault

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// EnsureVaultClient guarantees the Vault client is set, using the privileged eos user.
func EnsureVaultClient(log *zap.Logger) {
	log.Debug("🔐 Ensuring VAULT_ADDR is configured...")

	var client *api.Client
	var report *CheckReport
	var checkedClient *api.Client

	if _, err := EnsureVaultEnv(log); err != nil {
		log.Warn("⚠️ Failed to set Vault environment", zap.Error(err))
	}

	if client, err := GetVaultClient(log); err == nil && client != nil {
		log.Debug("✅ Vault client already initialized")
		// ✅ Validate it works
		// 🔍 Run full Vault diagnostics
		report, checkedClient := Check(client, log, nil, "")
		if checkedClient != nil {
			SetVaultClient(checkedClient, log)
		}

		if report == nil {
			log.Warn("⚠️ Vault check returned nil — skipping further setup")
			return
		}

		if len(report.Notes) > 0 {
			for _, note := range report.Notes {
				log.Warn("⚠️ Vault diagnostic note", zap.String("note", note))
			}
		}
		return
	}

	report, checkedClient = Check(client, log, nil, "")
	if checkedClient != nil {
		SetVaultClient(checkedClient, log)
	}
	if report == nil {
		log.Warn("⚠️ Vault check returned nil — skipping further setup")
		return
	}
	if len(report.Notes) > 0 {
		for _, note := range report.Notes {
			log.Warn("⚠️ Vault diagnostic note", zap.String("note", note))
		}
	}

	log.Info("🔐 Attempting to initialize Vault client from environment (VAULT_TOKEN)...")
	client, err := NewClient(log)
	if err == nil {
		log.Info("✅ Vault client created from environment")
		SetVaultClient(client, log)

		// ✅ Validate health
		report, checkedClient := Check(client, log, nil, "")
		if checkedClient != nil {
			SetVaultClient(checkedClient, log)
		}
		if report == nil {
			log.Warn("⚠️ Vault check returned nil — skipping further setup")
			return
		}
		if len(report.Notes) > 0 {
			for _, note := range report.Notes {
				log.Warn("⚠️ Vault diagnostic note", zap.String("note", note))
			}
		}
		return
	}

	log.Warn("⚠️ Failed to create Vault client from environment", zap.Error(err))
	log.Info("🔐 Falling back to Vault Agent AppRole authentication...")

	client, err = GetPrivilegedVaultClient(log)
	if err != nil {
		log.Error("❌ Vault client could not be initialized",
			zap.Error(err),
			zap.String("hint", "Is Vault Agent running? Is /run/eos/vault-agent-eos.token readable? Did you run `eos secure vault`?"),
		)
		return
	}

	log.Info("✅ Vault client initialized via privileged agent")
	SetVaultClient(client, log)

	// ✅ Validate health
	report, checkedClient = Check(client, log, nil, "")
	if checkedClient != nil {
		SetVaultClient(checkedClient, log)
	}
	if report == nil {
		log.Warn("⚠️ Vault check returned nil — skipping further setup")
		return
	}
	if len(report.Notes) > 0 {
		for _, note := range report.Notes {
			log.Warn("⚠️ Vault diagnostic note", zap.String("note", note))
		}
	}
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
