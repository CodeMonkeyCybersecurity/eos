package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.uber.org/zap"
)

var tracer = otel.Tracer("eos/pkg/vault")

var (
	vaultClientLock sync.Mutex
)

// NewClient creates a new Vault API client using Eos-configured defaults.
func NewClient(rc *eos_io.RuntimeContext) (*api.Client, error) {
	log := otelzap.Ctx(rc.Ctx)

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

	// If no VAULT_CACERT, use the Eos default cert path
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

	// Check for VAULT_TOKEN but log it for debugging
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		log.Warn("VAULT_TOKEN found in environment during client creation")
		client.SetToken(token)
		log.Info(" Vault token loaded from VAULT_TOKEN environment variable")
	} else {
		log.Info(" No VAULT_TOKEN in environment - client created without token")
	}

	log.Info(" Vault client created", zap.String("addr", cfg.Address))
	return client, nil
}

// ==========================
// PUBLIC ACCESSORS
// ==========================

// GetVaultClient returns a cached or validated Vault client instance.
func GetVaultClient(rc *eos_io.RuntimeContext) (*api.Client, error) {
	vaultClientLock.Lock()
	defer vaultClientLock.Unlock()

	if shared.VaultClient != nil {
		otelzap.Ctx(rc.Ctx).Debug(" Returning cached Vault client")
		return shared.VaultClient, nil
	}

	otelzap.Ctx(rc.Ctx).Warn("Vault client not initialized — bootstrapping...")
	client, err := initializeClient(rc)
	if err != nil {
		return nil, err
	}
	shared.VaultClient = client
	otelzap.Ctx(rc.Ctx).Info(" Vault client cached and ready")
	return client, nil
}

// SetVaultClient explicitly sets the global Vault client.
func SetVaultClient(rc *eos_io.RuntimeContext, client *api.Client) {
	vaultClientLock.Lock()
	defer vaultClientLock.Unlock()
	shared.VaultClient = client
	otelzap.Ctx(rc.Ctx).Debug(" Global Vault client set")
}

// ==========================
// CLIENT INITIALIZATION
// ==========================

func initializeClient(rc *eos_io.RuntimeContext) (*api.Client, error) {

	log := otelzap.Ctx(rc.Ctx)

	client, err := tryEnvOrFallback(rc)
	if err != nil {

		return nil, cerr.Wrap(err, "bootstrap Vault client failed")
	}

	validated, report := validateClient(rc, client)
	if validated == nil {
		err := cerr.New("vault client failed health check")
		log.Error(" Client validation failed")

		return nil, err
	}

	for _, note := range report.Notes {
		log.Warn(" Vault validation note", zap.String("note", note))
	}

	log.Info(" Vault client validated and ready")
	return validated, nil
}

func tryEnvOrFallback(rc *eos_io.RuntimeContext) (*api.Client, error) {
	_, span := tracer.Start(rc.Ctx, "vault.tryEnvOrFallback")
	defer span.End()

	log := otelzap.Ctx(rc.Ctx)

	if c, err := buildClientFromEnv(rc); err == nil {
		span.SetStatus(codes.Ok, "client loaded from env")
		return c, nil
	} else {
		log.Warn("Failed to load Vault client from environment", zap.Error(err))
		span.RecordError(err)
	}

	log.Info(" Falling back to privileged client")
	client, err := buildPrivilegedClient(rc)
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

func buildClientFromEnv(rc *eos_io.RuntimeContext) (*api.Client, error) {
	client, err := newConfiguredClient(rc)
	if err != nil {
		return nil, fmt.Errorf("env client error: %w", err)
	}
	otelzap.Ctx(rc.Ctx).Info(" Vault client constructed from environment")
	return client, nil
}

func buildPrivilegedClient(rc *eos_io.RuntimeContext) (*api.Client, error) {
	token, err := loadPrivilegedToken(rc)
	if err != nil {
		return nil, err
	}

	client, err := newConfiguredClient(rc)
	if err != nil {
		return nil, fmt.Errorf("privileged client error: %w", err)
	}
	client.SetToken(token)

	otelzap.Ctx(rc.Ctx).Info(" Vault privileged client constructed")
	return client, nil
}

// ==========================
// CONFIG + BASE CLIENT
// ==========================

func newConfiguredClient(rc *eos_io.RuntimeContext) (*api.Client, error) {
	addr, _ := EnsureVaultEnv(rc)
	cfg := api.DefaultConfig()
	cfg.Address = addr
	cfg.Timeout = 5 * time.Second

	if err := cfg.ReadEnvironment(); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Could not load Vault env config", zap.Error(err))
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

func loadPrivilegedToken(rc *eos_io.RuntimeContext) (string, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Loading privileged token for Vault authentication")

	// For enable command, we should ALWAYS use the root token from vault_init.json
	// The Vault Agent token won't have permissions to create mounts and manage auth methods
	log.Info(" Loading root token from vault_init.json for provisioning operations")

	// Skip agent token check - go directly to root token for enable operations
	log.Info(" Reading root token from vault_init.json")
	token, err := readTokenFromInitFile(rc)
	if err != nil {
		log.Error(" Failed to read root token from init file", zap.Error(err))

		// Only try agent token as last resort
		log.Warn(" Attempting to read Vault Agent token as fallback")
		if agentToken, agentErr := readTokenFromSink(rc, shared.AgentToken); agentErr == nil {
			log.Warn("Using Vault Agent token - this may not have sufficient privileges")
			return agentToken, nil
		}

		return "", fmt.Errorf("failed to load any privileged token: %w", err)
	}

	log.Info(" Successfully loaded root token from init file",
		zap.String("source", "/var/lib/eos/secrets/vault_init.json"))
	return token, nil
}

func readTokenFromInitFile(rc *eos_io.RuntimeContext) (string, error) {
	log := otelzap.Ctx(rc.Ctx)
	path := filepath.Join(shared.SecretsDir, "vault_init.json")

	log.Info(" Reading root token from init file", zap.String("path", path))

	// Check if secrets directory exists
	if dirStat, err := os.Stat(shared.SecretsDir); err != nil {
		if os.IsNotExist(err) {
			log.Error(" Secrets directory does not exist",
				zap.String("dir", shared.SecretsDir),
				zap.Error(err))
			return "", fmt.Errorf("secrets directory does not exist: %s", shared.SecretsDir)
		}
		log.Error(" Cannot access secrets directory",
			zap.String("dir", shared.SecretsDir),
			zap.Error(err))
		return "", fmt.Errorf("cannot access secrets directory %s: %w", shared.SecretsDir, err)
	} else {
		log.Info(" Secrets directory accessible",
			zap.String("dir", shared.SecretsDir),
			zap.String("mode", dirStat.Mode().String()))
	}

	// Check if init file exists and get its permissions
	if stat, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			log.Error(" vault_init.json does not exist",
				zap.String("path", path),
				zap.Error(err))
			return "", fmt.Errorf("vault_init.json does not exist at %s", path)
		}
		log.Error(" Cannot access vault_init.json",
			zap.String("path", path),
			zap.Error(err))
		return "", fmt.Errorf("cannot access vault_init.json at %s: %w", path, err)
	} else {
		log.Info(" vault_init.json file found",
			zap.String("path", path),
			zap.String("mode", stat.Mode().String()),
			zap.Int64("size", stat.Size()),
			zap.Time("mod_time", stat.ModTime()))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Error(" Failed to read vault_init.json file",
			zap.String("path", path),
			zap.Error(err))
		return "", fmt.Errorf("read vault_init.json: %w", err)
	}
	log.Info(" vault_init.json file read successfully",
		zap.String("path", path),
		zap.Int("data_length", len(data)))

	var init shared.VaultInitResponse
	if err := json.Unmarshal(data, &init); err != nil {
		log.Error(" Failed to unmarshal vault_init.json",
			zap.String("path", path),
			zap.Error(err))
		return "", fmt.Errorf("unmarshal vault_init.json: %w", err)
	}

	if init.RootToken == "" {
		log.Error(" vault_init.json contains no root token",
			zap.String("path", path))
		return "", fmt.Errorf("vault_init.json contains no root token")
	}

	log.Info(" Root token extracted from vault_init.json",
		zap.String("path", path))
	return init.RootToken, nil
}

// ==========================
// VALIDATION
// ==========================

func validateClient(rc *eos_io.RuntimeContext, client *api.Client) (*api.Client, *shared.CheckReport) {
	_, span := tracer.Start(context.Background(), "vault.validateClient")
	defer span.End()

	report, fixedClient := Check(rc, client, nil, "")
	if fixedClient != nil {
		client = fixedClient
	}
	if report == nil {
		err := cerr.New("vault client failed health check")
		otelzap.Ctx(rc.Ctx).Warn("Vault Check returned nil report", zap.Error(err))
		span.SetStatus(codes.Error, "nil report from vault.Check")
		span.RecordError(err)
		return nil, nil
	}

	span.SetStatus(codes.Ok, "Vault client validated")
	return client, report
}
