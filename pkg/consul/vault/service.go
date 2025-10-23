package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GenerateServiceConfig creates a Consul service registration for Vault
// DEPRECATED: Use VaultIntegration.RegisterVault() instead for SDK-based registration with ACL support
// Migrated from cmd/create/consul.go generateVaultServiceConfig
func GenerateServiceConfig(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check prerequisites
	log.Info("Assessing Vault service registration requirements")

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		return fmt.Errorf("VAULT_ADDR not set")
	}

	hostname := eos_unix.GetInternalHostname()

	// Extract hostname and port from VAULT_ADDR
	vaultURL := strings.TrimPrefix(vaultAddr, "https://")
	vaultURL = strings.TrimPrefix(vaultURL, "http://")

	parts := strings.Split(vaultURL, ":")
	vaultHost := parts[0]
	vaultPort := "8200" // default
	if len(parts) > 1 {
		vaultPort = parts[1]
	}

	// INTERVENE - Generate and write service configuration
	log.Info("Generating Vault service registration for Consul",
		zap.String("vault_addr", vaultAddr),
		zap.String("vault_host", vaultHost),
		zap.String("vault_port", vaultPort))

	serviceConfig := fmt.Sprintf(`{
  "service": {
    "name": "vault",
    "id": "vault-%s",
    "port": %s,
    "address": "%s",
    "tags": [
      "active",
      "tls",
      "file-backend",
      "primary",
      "eos-managed"
    ],
    "meta": {
      "version": "1.15.0",
      "storage_type": "file", 
      "instance": "%s",
      "environment": "production",
      "eos_managed": "true"
    },
    "check": {
      "id": "vault-health",
      "name": "Vault HTTPS Health",
      "http": "%s/v1/sys/health?standbyok=true&perfstandbyok=true",
      "interval": "10s",
      "timeout": "5s",
      "tls_skip_verify": true,
      "success_before_passing": 2,
      "failures_before_critical": 3
    },
    "weights": {
      "passing": 10,
      "warning": 1
    }
  }
}`, hostname, vaultPort, vaultHost, hostname, vaultAddr)

	servicePath := consul.ConsulVaultServiceConfig
	if err := os.WriteFile(servicePath, []byte(serviceConfig), consul.ConsulConfigPerm); err != nil {
		return fmt.Errorf("failed to write vault service config: %w", err)
	}

	// Set ownership
	ownerStr := fmt.Sprintf("%s:%s", consul.ConsulUser, consul.ConsulGroup)
	if err := execute.RunSimple(rc.Ctx, "chown", ownerStr, servicePath); err != nil {
		return fmt.Errorf("failed to set service config ownership: %w", err)
	}

	// EVALUATE - Verify service configuration was written
	log.Info("Evaluating Vault service registration")

	info, err := os.Stat(servicePath)
	if err != nil {
		return fmt.Errorf("failed to verify service config file: %w", err)
	}

	if info.Mode().Perm() != consul.ConsulConfigPerm {
		log.Warn("Service config file permissions not as expected",
			zap.String("expected", fmt.Sprintf("%04o", consul.ConsulConfigPerm)),
			zap.String("actual", info.Mode().Perm().String()))
	}

	log.Info("Vault service registration created successfully",
		zap.String("path", servicePath),
		zap.String("service_id", fmt.Sprintf("vault-%s", hostname)))

	return nil
}
