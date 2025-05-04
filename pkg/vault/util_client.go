package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

var vaultClientLock sync.Mutex

// GetVaultClient returns a cached or freshly initialized and validated Vault client.
func GetVaultClient() (*api.Client, error) {
	vaultClientLock.Lock()
	defer vaultClientLock.Unlock()

	if shared.VaultClient != nil {
		zap.L().Debug("📦 Returning cached Vault client")
		return shared.VaultClient, nil
	}

	zap.L().Warn("⚠️ Vault client uninitialized — initializing...")

	client, err := tryEnvOrPrivilegedClient()
	if err != nil {
		return nil, err
	}

	validated, _ := validateClient(client)
	if validated == nil {
		return nil, fmt.Errorf("initialized Vault client failed health validation")
	}

	shared.VaultClient = validated
	zap.L().Info("✅ Vault client initialized, validated, and cached")
	return shared.VaultClient, nil
}

// SetVaultClient caches a Vault client globally.
func SetVaultClient(client *api.Client) {
	vaultClientLock.Lock()
	defer vaultClientLock.Unlock()
	zap.L().Debug("📦 Vault client cached globally")
	shared.VaultClient = client
}

// tryEnvOrPrivilegedClient tries an environment-based client first, then privileged fallback.
func tryEnvOrPrivilegedClient() (*api.Client, error) {
	client, err := newClientWithEnv()
	if err == nil {
		return client, nil
	}
	zap.L().Warn("⚠️ Environment client failed, trying privileged fallback")
	return newPrivilegedClient()
}

// newClientWithEnv creates a Vault client using environment variables.
func newClientWithEnv() (*api.Client, error) {
	client, err := NewClient()
	if err != nil {
		return nil, fmt.Errorf("env client creation failed: %w", err)
	}
	zap.L().Info("✅ Vault client created from environment")
	return client, nil
}

// newPrivilegedClient creates a Vault client using agent or root token fallback.
func newPrivilegedClient() (*api.Client, error) {
	token, err := readTokenFromSink(shared.VaultAgentTokenPath)
	if err != nil {
		zap.L().Warn("⚠️ Vault Agent token not found, falling back to vault_init.json", zap.Error(err))
		token, err = readRootTokenFromInitFile()
		if err != nil {
			return nil, err
		}
	}

	client, err := NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create new client: %w", err)
	}
	client.SetToken(token)
	zap.L().Info("✅ Privileged Vault client ready")
	return client, nil
}

// readRootTokenFromInitFile loads the root token from vault_init.json.
func readRootTokenFromInitFile() (string, error) {
	path := filepath.Join(shared.SecretsDir, "vault_init.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read vault_init.json: %w", err)
	}

	var initRes shared.VaultInitResponse
	if err := json.Unmarshal(data, &initRes); err != nil {
		return "", fmt.Errorf("failed to unmarshal vault_init.json: %w", err)
	}
	if initRes.RootToken == "" {
		return "", fmt.Errorf("vault_init.json contains empty root token")
	}
	return initRes.RootToken, nil
}

// NewClient sets up a Vault API client with env and TLS config.
func NewClient() (*api.Client, error) {
	addr, _ := EnsureVaultEnv()
	cfg := api.DefaultConfig()
	cfg.Address = addr

	if err := cfg.ReadEnvironment(); err != nil {
		zap.L().Warn("⚠️ could not read Vault env config", zap.Error(err))
	}

	if os.Getenv("VAULT_CACERT") == "" {
		if err := cfg.ConfigureTLS(&api.TLSConfig{CACert: shared.TLSCrt}); err != nil {
			return nil, fmt.Errorf("tls-config: %w", err)
		}
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("new-client: %w", err)
	}

	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		client.SetToken(token)
	}
	return client, nil
}

// validateClient checks Vault health and logs any diagnostic notes.
func validateClient(client *api.Client) (*api.Client, *shared.CheckReport) {
	report, checkedClient := Check(client, nil, "")
	if checkedClient != nil {
		client = checkedClient
	}
	if report == nil {
		zap.L().Warn("⚠️ Vault check returned nil — skipping further setup")
		return nil, nil
	}
	for _, note := range report.Notes {
		zap.L().Warn("⚠️ Vault diagnostic note", zap.String("note", note))
	}
	return client, report
}
