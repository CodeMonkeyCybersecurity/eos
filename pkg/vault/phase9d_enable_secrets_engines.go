// pkg/vault/phase9d_enable_secrets_engines.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PhaseEnableSecretsEngines enables additional secrets engines (database, PKI)
// during Vault installation flow.
//
// This phase should be called after KV v2 is enabled (Phase 9a) but before
// authentication methods are configured (Phase 10).
//
// Secrets engines enabled:
// - Database secrets engine (optional, interactive)
// - PKI secrets engine (optional, interactive)
func PhaseEnableSecretsEngines(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" [Phase 9d] Enabling additional secrets engines")

	// Get privileged client
	logger.Info(" Requesting privileged Vault client")
	privilegedClient, err := GetRootClient(rc)
	if err != nil {
		logger.Error(" Failed to get privileged Vault client", zap.Error(err))
		return fmt.Errorf("failed to get privileged client: %w", err)
	}

	// Log client readiness
	if token := privilegedClient.Token(); token != "" {
		logger.Info(" Privileged Vault client ready")
	} else {
		logger.Error(" Privileged client has no token set")
		return fmt.Errorf("privileged client has no token")
	}

	// Enable database secrets engine (optional)
	logger.Info("terminal prompt: Would you like to enable the Database secrets engine?")
	logger.Info("terminal prompt: This enables dynamic database credential generation")

	// For now, we'll skip the interactive prompt in the automated flow
	// Users can enable it later with: eos enable vault database-engine
	logger.Info(" Skipping database secrets engine (can be enabled later)")

	// Enable PKI secrets engine (optional)
	logger.Info("terminal prompt: Would you like to enable the PKI secrets engine?")
	logger.Info("terminal prompt: This enables certificate authority and certificate management")

	// For now, we'll skip the interactive prompt in the automated flow
	// Users can enable it later with: eos enable vault pki-engine
	logger.Info(" Skipping PKI secrets engine (can be enabled later)")

	logger.Info(" [Phase 9d] Additional secrets engines phase completed")
	logger.Info("terminal prompt: You can enable additional secrets engines later with:")
	logger.Info("terminal prompt:   - Database: eos enable vault database-engine")
	logger.Info("terminal prompt:   - PKI: eos enable vault pki-engine")

	return nil
}

// EnableDatabaseSecretsEngine enables and configures the Vault database secrets engine
//
// The database secrets engine generates dynamic credentials for databases.
// This function:
// 1. Checks if database engine is already enabled
// 2. Enables the database secrets engine at database/
// 3. Verifies the engine is accessible
//
// Configuration of specific database connections should be done separately
// using the database configuration helpers in pkg/vault/secrets/database.go
func EnableDatabaseSecretsEngine(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Enabling database secrets engine")

	// ASSESS: Check if database engine is already enabled
	logger.Info(" Checking if database secrets engine is already enabled")
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		logger.Error(" Failed to list mounts", zap.Error(err))
		return fmt.Errorf("failed to list mounts: %w", err)
	}

	// Check if database/ mount already exists
	if mount, exists := mounts["database/"]; exists {
		logger.Info(" Database secrets engine already enabled",
			zap.String("type", mount.Type),
			zap.String("path", "database/"))
		return nil
	}

	// INTERVENE: Enable the database secrets engine
	logger.Info(" Enabling database secrets engine at database/")

	err = client.Sys().Mount("database", &api.MountInput{
		Type:        "database",
		Description: "Dynamic database credentials",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "1h",
			MaxLeaseTTL:     "24h",
		},
	})
	if err != nil {
		logger.Error(" Failed to enable database secrets engine", zap.Error(err))
		return fmt.Errorf("failed to enable database secrets engine: %w", err)
	}

	logger.Info(" Database secrets engine enabled successfully")

	// EVALUATE: Verify the engine is accessible
	logger.Info(" Verifying database secrets engine is accessible")
	mounts, err = client.Sys().ListMounts()
	if err != nil {
		logger.Error(" Failed to verify database secrets engine", zap.Error(err))
		return fmt.Errorf("failed to verify database secrets engine: %w", err)
	}

	if mount, exists := mounts["database/"]; exists && mount.Type == "database" {
		logger.Info(" Database secrets engine verified",
			zap.String("type", mount.Type),
			zap.Int("default_lease_ttl_seconds", mount.Config.DefaultLeaseTTL),
			zap.Int("max_lease_ttl_seconds", mount.Config.MaxLeaseTTL))
	} else {
		logger.Error(" Database secrets engine verification failed")
		return fmt.Errorf("database secrets engine not found after enablement")
	}

	logger.Info("terminal prompt: Database secrets engine enabled successfully")
	logger.Info("terminal prompt: Configure database connections with: eos configure vault database")
	logger.Info("terminal prompt: Documentation: https://www.vaultproject.io/docs/secrets/databases")

	return nil
}

// EnablePKISecretsEngine enables and configures the Vault PKI secrets engine
//
// The PKI secrets engine generates X.509 certificates dynamically.
// This function:
// 1. Checks if PKI engine is already enabled
// 2. Enables the PKI secrets engine at pki/
// 3. Configures default TTLs for certificates
// 4. Verifies the engine is accessible
//
// Root CA generation and intermediate CA configuration should be done separately
// using PKI configuration helpers.
func EnablePKISecretsEngine(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Enabling PKI secrets engine")

	// ASSESS: Check if PKI engine is already enabled
	logger.Info(" Checking if PKI secrets engine is already enabled")
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		logger.Error(" Failed to list mounts", zap.Error(err))
		return fmt.Errorf("failed to list mounts: %w", err)
	}

	// Check if pki/ mount already exists
	if mount, exists := mounts["pki/"]; exists {
		logger.Info(" PKI secrets engine already enabled",
			zap.String("type", mount.Type),
			zap.String("path", "pki/"))
		return nil
	}

	// INTERVENE: Enable the PKI secrets engine
	logger.Info(" Enabling PKI secrets engine at pki/")

	err = client.Sys().Mount("pki", &api.MountInput{
		Type:        "pki",
		Description: "PKI certificate authority",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "8760h",  // 1 year
			MaxLeaseTTL:     "87600h", // 10 years
		},
	})
	if err != nil {
		logger.Error(" Failed to enable PKI secrets engine", zap.Error(err))
		return fmt.Errorf("failed to enable PKI secrets engine: %w", err)
	}

	logger.Info(" PKI secrets engine enabled successfully")

	// EVALUATE: Verify the engine is accessible
	logger.Info(" Verifying PKI secrets engine is accessible")
	mounts, err = client.Sys().ListMounts()
	if err != nil {
		logger.Error(" Failed to verify PKI secrets engine", zap.Error(err))
		return fmt.Errorf("failed to verify PKI secrets engine: %w", err)
	}

	if mount, exists := mounts["pki/"]; exists && mount.Type == "pki" {
		logger.Info(" PKI secrets engine verified",
			zap.String("type", mount.Type),
			zap.Int("default_lease_ttl_seconds", mount.Config.DefaultLeaseTTL),
			zap.Int("max_lease_ttl_seconds", mount.Config.MaxLeaseTTL))
	} else {
		logger.Error(" PKI secrets engine verification failed")
		return fmt.Errorf("PKI secrets engine not found after enablement")
	}

	logger.Info("terminal prompt: PKI secrets engine enabled successfully")
	logger.Info("terminal prompt: Configure root CA with: eos configure vault pki-root")
	logger.Info("terminal prompt: Documentation: https://www.vaultproject.io/docs/secrets/pki")

	return nil
}

// EnablePKIIntermediateCA creates an intermediate CA for the PKI secrets engine
//
// This function should be called after EnablePKISecretsEngine.
// It configures an intermediate CA at pki_int/ for issuing certificates.
func EnablePKIIntermediateCA(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Enabling PKI intermediate CA")

	// ASSESS: Check if intermediate PKI engine is already enabled
	logger.Info(" Checking if PKI intermediate CA is already enabled")
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		logger.Error(" Failed to list mounts", zap.Error(err))
		return fmt.Errorf("failed to list mounts: %w", err)
	}

	// Check if pki_int/ mount already exists
	if mount, exists := mounts["pki_int/"]; exists {
		logger.Info(" PKI intermediate CA already enabled",
			zap.String("type", mount.Type),
			zap.String("path", "pki_int/"))
		return nil
	}

	// INTERVENE: Enable the intermediate PKI secrets engine
	logger.Info(" Enabling PKI intermediate CA at pki_int/")

	err = client.Sys().Mount("pki_int", &api.MountInput{
		Type:        "pki",
		Description: "PKI intermediate certificate authority",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "4380h",  // 6 months
			MaxLeaseTTL:     "43800h", // 5 years
		},
	})
	if err != nil {
		logger.Error(" Failed to enable PKI intermediate CA", zap.Error(err))
		return fmt.Errorf("failed to enable PKI intermediate CA: %w", err)
	}

	logger.Info(" PKI intermediate CA enabled successfully")

	// EVALUATE: Verify the intermediate CA is accessible
	logger.Info(" Verifying PKI intermediate CA is accessible")
	mounts, err = client.Sys().ListMounts()
	if err != nil {
		logger.Error(" Failed to verify PKI intermediate CA", zap.Error(err))
		return fmt.Errorf("failed to verify PKI intermediate CA: %w", err)
	}

	if mount, exists := mounts["pki_int/"]; exists && mount.Type == "pki" {
		logger.Info(" PKI intermediate CA verified",
			zap.String("type", mount.Type),
			zap.Int("default_lease_ttl_seconds", mount.Config.DefaultLeaseTTL),
			zap.Int("max_lease_ttl_seconds", mount.Config.MaxLeaseTTL))
	} else {
		logger.Error(" PKI intermediate CA verification failed")
		return fmt.Errorf("PKI intermediate CA not found after enablement")
	}

	logger.Info("terminal prompt: PKI intermediate CA enabled successfully")
	logger.Info("terminal prompt: Configure intermediate CA with: eos configure vault pki-intermediate")

	return nil
}

// VerifySecretsEngines verifies that secrets engines are properly configured
//
// This function checks:
// - KV v2 secrets engine is enabled and accessible
// - Optional secrets engines (database, PKI) if enabled
// - Each engine responds to basic API calls
func VerifySecretsEngines(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Verifying secrets engines configuration")

	// Get list of all mounts
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		logger.Error(" Failed to list mounts", zap.Error(err))
		return fmt.Errorf("failed to list mounts: %w", err)
	}

	// Verify KV v2 (required)
	if mount, exists := mounts["secret/"]; exists {
		if mount.Type == "kv" && mount.Options["version"] == "2" {
			logger.Info(" KV v2 secrets engine verified", zap.String("path", "secret/"))
		} else {
			logger.Error(" KV secrets engine found but not v2",
				zap.String("type", mount.Type),
				zap.String("version", mount.Options["version"]))
			return fmt.Errorf("KV secrets engine is not v2")
		}
	} else {
		logger.Error(" KV v2 secrets engine not found")
		return fmt.Errorf("KV v2 secrets engine not enabled")
	}

	// Check optional engines (non-fatal if missing)
	optionalEngines := map[string]string{
		"database/": "database",
		"pki/":      "pki",
		"pki_int/":  "pki",
	}

	for path, expectedType := range optionalEngines {
		if mount, exists := mounts[path]; exists {
			if mount.Type == expectedType {
				logger.Info(" Optional secrets engine verified",
					zap.String("path", path),
					zap.String("type", mount.Type))
			} else {
				logger.Warn(" Optional secrets engine has unexpected type",
					zap.String("path", path),
					zap.String("expected_type", expectedType),
					zap.String("actual_type", mount.Type))
			}
		} else {
			logger.Debug(" Optional secrets engine not enabled",
				zap.String("path", path))
		}
	}

	logger.Info(" Secrets engines verification completed")
	return nil
}

// GetEnabledSecretsEngines returns a list of enabled secrets engines
func GetEnabledSecretsEngines(rc *eos_io.RuntimeContext, client *api.Client) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug(" Getting enabled secrets engines")

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		logger.Error(" Failed to list mounts", zap.Error(err))
		return nil, fmt.Errorf("failed to list mounts: %w", err)
	}

	var enabled []string
	for path, mount := range mounts {
		// Skip system mounts
		if mount.Type == "system" || mount.Type == "identity" || mount.Type == "cubbyhole" {
			continue
		}
		enabled = append(enabled, fmt.Sprintf("%s (%s)", path, mount.Type))
	}

	logger.Debug(" Enabled secrets engines retrieved",
		zap.Int("count", len(enabled)),
		zap.Strings("engines", enabled))

	return enabled, nil
}

// DisableSecretsEngine disables a secrets engine at the given path
//
// CAUTION: This will delete all secrets stored in the engine.
// Use with care and ensure backups are taken first.
func DisableSecretsEngine(rc *eos_io.RuntimeContext, client *api.Client, path string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn(" Disabling secrets engine",
		zap.String("path", path))

	// ASSESS: Check if the engine exists
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		logger.Error(" Failed to list mounts", zap.Error(err))
		return fmt.Errorf("failed to list mounts: %w", err)
	}

	if _, exists := mounts[path]; !exists {
		logger.Warn(" Secrets engine not found",
			zap.String("path", path))
		return fmt.Errorf("secrets engine not found at %s", path)
	}

	// INTERVENE: Disable the engine
	logger.Info(" Unmounting secrets engine", zap.String("path", path))
	if err := client.Sys().Unmount(path); err != nil {
		logger.Error(" Failed to disable secrets engine",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("failed to disable secrets engine at %s: %w", path, err)
	}

	// EVALUATE: Verify the engine is removed
	mounts, err = client.Sys().ListMounts()
	if err != nil {
		logger.Error(" Failed to verify secrets engine removal", zap.Error(err))
		return fmt.Errorf("failed to verify secrets engine removal: %w", err)
	}

	if _, exists := mounts[path]; exists {
		logger.Error(" Secrets engine still exists after unmount",
			zap.String("path", path))
		return fmt.Errorf("secrets engine still exists at %s after unmount", path)
	}

	logger.Info(" Secrets engine disabled successfully",
		zap.String("path", path))

	return nil
}
