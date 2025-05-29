// pkg/vault/tls.go

package vault

import (
	"context"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	cerr "github.com/cockroachdb/errors"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.uber.org/zap"
)

// GetTLSCertPath resolves the Vault TLS client certificate path.
// Priority:
//  1. VAULT_CLIENT_CERT env var
//  2. vaultapi.Config.TLSConfig.ClientCert (via vaultapi.DefaultConfig)
func GetTLSCertPath(rc *eos_io.RuntimeContext) (string, error) {
	_, span := tracer.Start(context.Background(), "vault.GetTLSCertPath")
	defer span.End()

	log := otelzap.Ctx(rc.Ctx)

	// 1️⃣ Check VAULT_CLIENT_CERT env
	if path := os.Getenv("VAULT_CLIENT_CERT"); path != "" {
		log.Debug("🔐 Found client cert via VAULT_CLIENT_CERT", zap.String("path", path))
		span.SetAttributes(attribute.String("vault.client_cert.source", "env"))
		span.SetStatus(codes.Ok, "cert path resolved from env")
		return path, nil
	}

	// 2️⃣ Fallback to vaultapi.DefaultConfig
	cfg := vaultapi.DefaultConfig()
	if err := cfg.ReadEnvironment(); err != nil {
		log.Warn("⚠️ Failed to read Vault env config", zap.Error(err))
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to read env")
		return "", cerr.Wrap(err, "unable to read Vault environment config")
	}

	tlsCfg := vaultapi.TLSConfig{}
	if err := cfg.ConfigureTLS(&tlsCfg); err != nil {
		log.Error("❌ Failed to configure TLS from environment", zap.Error(err))
		span.RecordError(err)
		span.SetStatus(codes.Error, "TLS config failed")
		return "", cerr.Wrap(err, "vault TLS configuration error")
	}

	if tlsCfg.ClientCert != "" {
		log.Debug("📄 Using TLS client cert from config", zap.String("path", tlsCfg.ClientCert))
		span.SetAttributes(attribute.String("vault.client_cert.source", "config"))
		span.SetStatus(codes.Ok, "cert path resolved from config")
		return tlsCfg.ClientCert, nil
	}

	// 3️⃣ Not found
	err := cerr.New("no client TLS cert found: neither VAULT_CLIENT_CERT nor config TLS.ClientCert are set")
	log.Warn("❌ No client TLS certificate found", zap.Error(err))
	span.RecordError(err)
	span.SetStatus(codes.Error, "TLS client cert missing")
	return "", err
}
