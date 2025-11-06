// Package postinstall provides post-installation configuration for Moni (BionicGPT)
// following the Assess → Intervene → Evaluate pattern.
//
// Post-Installation Process:
//  1. ASSESS: Check PostgreSQL and LiteLLM are ready
//  2. INTERVENE:
//     a. Wait for PostgreSQL to be ready
//     b. Wait for LiteLLM to be ready
//     c. Upsert database models (safe UPSERT pattern)
//     d. Regenerate API keys
//  3. EVALUATE: Verify services are operational
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package postinstall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt/apikeys"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Config contains configuration for post-installation operations
type Config struct {
	// Installation paths
	InstallDir string // Base installation directory (default: /opt/bionicgpt)
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.InstallDir == "" {
		return fmt.Errorf("install directory cannot be empty")
	}
	return nil
}

// Execute runs the post-installation configuration
// Follows Assess → Intervene → Evaluate pattern
func Execute(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("🚀 Moni Post-Installation Configuration")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// ========================================
	// ASSESS: Check services are ready
	// ========================================
	logger.Info("Phase 1: Waiting for services to be ready")

	if err := waitForPostgreSQL(rc.Ctx); err != nil {
		return fmt.Errorf("PostgreSQL not ready: %w", err)
	}
	logger.Info("✅ PostgreSQL ready")

	if err := waitForLiteLLM(rc.Ctx); err != nil {
		return fmt.Errorf("LiteLLM not ready: %w", err)
	}
	logger.Info("✅ LiteLLM ready")

	// ========================================
	// INTERVENE: Configure database and API keys
	// ========================================
	logger.Info("Phase 2: Configuring database models")

	if err := upsertModels(rc.Ctx); err != nil {
		return fmt.Errorf("failed to upsert models: %w", err)
	}
	logger.Info("✅ Models updated")

	logger.Info("Phase 3: Regenerating API keys")

	apiKeysConfig := &apikeys.Config{
		InstallDir: config.InstallDir,
	}

	if err := apikeys.Execute(rc, apiKeysConfig); err != nil {
		return fmt.Errorf("failed to regenerate API keys: %w", err)
	}

	// ========================================
	// Summary
	// ========================================
	logger.Info("")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("✅ POST-INSTALLATION CONFIGURATION COMPLETE")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	return nil
}

// waitForPostgreSQL waits for PostgreSQL to be ready
func waitForPostgreSQL(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("⏳ Waiting for PostgreSQL...")

	timeout := time.After(bionicgpt.PostgresReadyTimeout)
	ticker := time.NewTicker(bionicgpt.PostgresReadyRetry)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for PostgreSQL after %v", bionicgpt.PostgresReadyTimeout)
		case <-ticker.C:
			cmd := exec.CommandContext(ctx,
				"docker", "exec", bionicgpt.ContainerPostgres,
				"pg_isready", "-U", bionicgpt.DefaultPostgresUser)

			if err := cmd.Run(); err == nil {
				return nil // PostgreSQL is ready
			}
			// Continue waiting
		}
	}
}

// waitForLiteLLM waits for LiteLLM health check to pass
func waitForLiteLLM(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("⏳ Waiting for LiteLLM...")

	timeout := time.After(60 * time.Second)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for LiteLLM after 60s")
		case <-ticker.C:
			cmd := exec.CommandContext(ctx,
				"curl", "-s", "http://localhost:4000/health/readiness")

			if err := cmd.Run(); err == nil {
				return nil // LiteLLM is ready
			}
			// Continue waiting
		}
	}
}

// upsertModels upserts the database models using INSERT ... ON CONFLICT
// CRITICAL: Uses UPSERT pattern (safe, won't delete existing data)
// SECURITY: All values are constants (no SQL injection risk)
func upsertModels(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("📝 Updating database models (safe upsert)")

	// SQL for upserting models
	// Uses INSERT ... ON CONFLICT DO UPDATE (PostgreSQL UPSERT)
	// RATIONALE: Safe operation - won't delete data, only updates if exists
	sql := `
INSERT INTO models (id, model_type, name, base_url, context_size, tpm_limit, rpm_limit, api_key)
VALUES
  (1, 'Embeddings', 'nomic-embed-text', 'http://litellm-proxy:4000', 8192, 10000, 10000, 'PLACEHOLDER'),
  (2, 'LLM', 'Moni', 'http://litellm-proxy:4000', 1000000, 50000, 1000, 'PLACEHOLDER'),
  (3, 'LLM', 'Moni-4.1', 'http://litellm-proxy:4000', 1000000, 30000, 500, 'PLACEHOLDER')
ON CONFLICT (id) DO UPDATE SET
  model_type = EXCLUDED.model_type,
  name = EXCLUDED.name,
  base_url = EXCLUDED.base_url,
  context_size = EXCLUDED.context_size,
  tpm_limit = EXCLUDED.tpm_limit,
  rpm_limit = EXCLUDED.rpm_limit,
  api_key = EXCLUDED.api_key;
`

	cmd := exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerPostgres,
		"psql", "-U", bionicgpt.DefaultPostgresUser, "-d", bionicgpt.DefaultPostgresDB,
		"-c", sql)

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to upsert models",
			zap.String("output", string(output)),
			zap.Error(err))
		return fmt.Errorf("failed to upsert models: %s: %w", string(output), err)
	}

	// Verify the upsert
	verifyCmd := exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerPostgres,
		"psql", "-U", bionicgpt.DefaultPostgresUser, "-d", bionicgpt.DefaultPostgresDB,
		"-t", "-c", "SELECT COUNT(*) FROM models WHERE id IN (1, 2, 3);")

	verifyOutput, err := verifyCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to verify models upsert: %w", err)
	}

	count := strings.TrimSpace(string(verifyOutput))
	if count != "3" {
		logger.Error("Model upsert verification failed",
			zap.String("expected_count", "3"),
			zap.String("actual_count", count))
		return fmt.Errorf("expected 3 models, found %s", count)
	}

	logger.Info("Models verified successfully", zap.String("count", count))
	return nil
}
