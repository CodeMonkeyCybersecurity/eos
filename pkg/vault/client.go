package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.uber.org/zap"
)

var tracer = otel.Tracer("eos/pkg/vault")

var (
	vaultClientLock sync.Mutex
)

// NewClient creates a new Vault API client using EOS-configured defaults.
func NewClient() (*api.Client, error) {
	log := zap.L().Named("vault.NewClient")

	// Fallback to default VAULT_ADDR if not set
	addr, ok := os.LookupEnv(shared.VaultAddrEnv)
	if !ok || addr == "" {
		addr = "http://127.0.0.1:8179"
		log.Warn("VAULT_ADDR not set, falling back to default", zap.String("addr", addr))
	}

	// Use Vault's default config and override address
	cfg := api.DefaultConfig()
	cfg.Address = addr

	// Load from environment (e.g., TLS vars)
	if err := cfg.ReadEnvironment(); err != nil {
		log.Warn("Unable to read Vault env vars", zap.Error(err))
	}

	// If no VAULT_CACERT, use the EOS default cert path
	if os.Getenv("VAULT_CACERT") == "" {
		err := cfg.ConfigureTLS(&api.TLSConfig{
			CACert: shared.TLSCrt,
		})
		if err != nil {
			return nil, fmt.Errorf("TLS setup failed: %w", err)
		}
		log.Debug("TLS config applied", zap.String("ca_cert", shared.TLSCrt))
	}

	// Create client
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault client creation failed: %w", err)
	}

	// Automatically use VAULT_TOKEN if available
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		client.SetToken(token)
		log.Debug("Vault token loaded from VAULT_TOKEN")
	}

	log.Info("✅ Vault client created", zap.String("addr", cfg.Address))
	return client, nil
}

// ==========================
// PUBLIC ACCESSORS
// ==========================

// GetVaultClient returns a cached or validated Vault client instance.
func GetVaultClient() (*api.Client, error) {
	vaultClientLock.Lock()
	defer vaultClientLock.Unlock()

	if shared.VaultClient != nil {
		zap.L().Debug("📦 Returning cached Vault client")
		return shared.VaultClient, nil
	}

	zap.L().Warn("⚠️ Vault client not initialized — bootstrapping...")
	client, err := initializeClient()
	if err != nil {
		return nil, err
	}
	shared.VaultClient = client
	zap.L().Info("✅ Vault client cached and ready")
	return client, nil
}

// SetVaultClient explicitly sets the global Vault client.
func SetVaultClient(client *api.Client) {
	vaultClientLock.Lock()
	defer vaultClientLock.Unlock()
	shared.VaultClient = client
	zap.L().Debug("📦 Global Vault client set")
}

// ==========================
// CLIENT INITIALIZATION
// ==========================

func initializeClient() (*api.Client, error) {
	ctx, span := tracer.Start(context.Background(), "vault.initializeClient")
	defer span.End()

	log := zap.L().Named("vault.initializeClient")

	client, err := tryEnvOrFallback(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "client bootstrap failed")
		return nil, cerr.Wrap(err, "bootstrap Vault client failed")
	}

	validated, report := validateClient(client)
	if validated == nil {
		err := cerr.New("vault client failed health check")
		log.Error("❌ Client validation failed")
		span.RecordError(err)
		span.SetStatus(codes.Error, "validation failed")
		return nil, err
	}

	for _, note := range report.Notes {
		log.Warn("📋 Vault validation note", zap.String("note", note))
	}

	span.SetStatus(codes.Ok, "client ready")
	log.Info("✅ Vault client validated and ready")
	return validated, nil
}

func tryEnvOrFallback(ctx context.Context) (*api.Client, error) {
	_, span := tracer.Start(ctx, "vault.tryEnvOrFallback")
	defer span.End()

	log := zap.L().Named("vault.tryEnvOrFallback")

	if c, err := buildClientFromEnv(); err == nil {
		span.SetStatus(codes.Ok, "client loaded from env")
		return c, nil
	} else {
		log.Warn("⚠️ Failed to load Vault client from environment", zap.Error(err))
		span.RecordError(err)
	}

	log.Info("🔐 Falling back to privileged client")
	client, err := buildPrivilegedClient()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "fallback failed")
		return nil, cerr.Wrap(err, "failed to initialize privileged Vault client")
	}

	span.SetStatus(codes.Ok, "fallback succeeded")
	return client, nil
}

// ==========================
// CLIENT CONSTRUCTORS
// ==========================

func buildClientFromEnv() (*api.Client, error) {
	client, err := newConfiguredClient()
	if err != nil {
		return nil, fmt.Errorf("env client error: %w", err)
	}
	zap.L().Info("✅ Vault client constructed from environment")
	return client, nil
}

func buildPrivilegedClient() (*api.Client, error) {
	token, err := loadPrivilegedToken()
	if err != nil {
		return nil, err
	}

	client, err := newConfiguredClient()
	if err != nil {
		return nil, fmt.Errorf("privileged client error: %w", err)
	}
	client.SetToken(token)

	zap.L().Info("✅ Vault privileged client constructed")
	return client, nil
}

// ==========================
// CONFIG + BASE CLIENT
// ==========================

func newConfiguredClient() (*api.Client, error) {
	addr, _ := EnsureVaultEnv()
	cfg := api.DefaultConfig()
	cfg.Address = addr
	cfg.Timeout = 5 * time.Second

	if err := cfg.ReadEnvironment(); err != nil {
		zap.L().Warn("⚠️ Could not load Vault env config", zap.Error(err))
	}

	if os.Getenv("VAULT_CACERT") == "" {
		if err := cfg.ConfigureTLS(&api.TLSConfig{CACert: shared.TLSCrt}); err != nil {
			return nil, fmt.Errorf("configure TLS: %w", err)
		}
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create Vault client: %w", err)
	}

	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		client.SetToken(token)
	}

	return client, nil
}

// ==========================
// TOKEN LOADERS
// ==========================

func loadPrivilegedToken() (string, error) {
	if token, err := readTokenFromSink(shared.AgentToken); err == nil {
		return token, nil
	}
	zap.L().Warn("⚠️ Agent token missing — fallback to vault_init.json")
	return readTokenFromInitFile()
}

func readTokenFromInitFile() (string, error) {
	path := filepath.Join(shared.SecretsDir, "vault_init.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read vault_init.json: %w", err)
	}

	var init shared.VaultInitResponse
	if err := json.Unmarshal(data, &init); err != nil {
		return "", fmt.Errorf("unmarshal vault_init.json: %w", err)
	}

	if init.RootToken == "" {
		return "", fmt.Errorf("vault_init.json contains no root token")
	}
	return init.RootToken, nil
}

// ==========================
// VALIDATION
// ==========================

func validateClient(client *api.Client) (*api.Client, *shared.CheckReport) {
	_, span := tracer.Start(context.Background(), "vault.validateClient")
	defer span.End()

	report, fixedClient := Check(client, nil, "")
	if fixedClient != nil {
		client = fixedClient
	}
	if report == nil {
		err := cerr.New("vault client failed health check")
		zap.L().Warn("⚠️ Vault Check returned nil report", zap.Error(err))
		span.SetStatus(codes.Error, "nil report from vault.Check")
		span.RecordError(err)
		return nil, nil
	}

	span.SetStatus(codes.Ok, "Vault client validated")
	return client, report
}
