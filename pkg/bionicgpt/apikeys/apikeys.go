// Package apikeys provides API key management for Moni (BionicGPT)
// following the Assess → Intervene → Evaluate pattern.
//
// API Key Rotation Process:
//  1. ASSESS: Check services, load configuration, show current state
//  2. INTERVENE:
//     a. Delete old virtual key from LiteLLM
//     b. Generate new virtual key with all models
//     c. Update .env file
//     d. Update database models
//     e. Restart application
//  3. EVALUATE: Verify authentication and database state
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package apikeys

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Config contains configuration for API key management
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

// keyGenerateResponse represents the response from LiteLLM key generation
type keyGenerateResponse struct {
	Key      string                 `json:"key"`
	KeyName  string                 `json:"key_name"`
	Expires  string                 `json:"expires"`
	UserID   string                 `json:"user_id"`
	Models   []string               `json:"models"`
	Metadata map[string]interface{} `json:"metadata"`
}

// modelsListResponse represents the response from LiteLLM models list
type modelsListResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

// Execute runs the API key rotation operation
// Follows Assess → Intervene → Evaluate pattern
func Execute(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("🔑 Moni API Key Management")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// ========================================
	// ASSESS: Load environment and check services
	// ========================================
	logger.Info("Phase 1: Loading environment configuration")

	envFile := filepath.Join(config.InstallDir, ".env")
	masterKey, currentVKey, err := loadEnvironment(rc.Ctx, envFile)
	if err != nil {
		return fmt.Errorf("failed to load environment: %w", err)
	}

	logger.Info("📋 Configuration loaded",
		zap.String("master_key", sanitizeKey(masterKey)),
		zap.String("current_virtual_key", sanitizeKey(currentVKey)))

	// Check database connection
	logger.Info("📊 Checking database connection")
	if err := checkDatabase(rc.Ctx); err != nil {
		return fmt.Errorf("database check failed: %w", err)
	}
	logger.Info("✅ Database is ready")

	// Check LiteLLM proxy
	logger.Info("🔄 Checking LiteLLM proxy")
	if err := checkLiteLLM(rc.Ctx); err != nil {
		return fmt.Errorf("LiteLLM check failed: %w", err)
	}
	logger.Info("✅ LiteLLM proxy is ready")

	// Show current database state
	logger.Info("📋 Current database state:")
	if err := showCurrentModels(rc.Ctx); err != nil {
		logger.Warn("Could not display current models", zap.Error(err))
	}

	// ========================================
	// INTERVENE: Generate new key and update
	// ========================================
	logger.Info("Phase 2: Generating new virtual key")

	// Delete old key if it exists
	if currentVKey != "" {
		logger.Info("Deleting old key", zap.String("key", sanitizeKey(currentVKey)))
		if err := deleteVirtualKey(rc.Ctx, masterKey, currentVKey); err != nil {
			logger.Warn("Failed to delete old key (may not exist)", zap.Error(err))
		}
	}

	// Generate new virtual key with all models
	newVKey, err := generateVirtualKey(rc.Ctx, masterKey)
	if err != nil {
		return fmt.Errorf("failed to generate virtual key: %w", err)
	}

	logger.Info("✅ Generated new virtual key", zap.String("key", sanitizeKey(newVKey)))

	// Update .env file
	logger.Info("Phase 3: Updating .env file")
	if err := updateEnvFile(rc.Ctx, envFile, newVKey); err != nil {
		return fmt.Errorf("failed to update .env file: %w", err)
	}
	logger.Info("✅ Updated .env file")

	// Update database
	logger.Info("Phase 4: Updating database")
	if err := updateDatabaseKeys(rc.Ctx, newVKey); err != nil {
		return fmt.Errorf("failed to update database: %w", err)
	}
	logger.Info("✅ Updated database")

	// Restart app
	logger.Info("Phase 5: Restarting Moni application")
	if err := restartApp(rc.Ctx, config.InstallDir); err != nil {
		return fmt.Errorf("failed to restart app: %w", err)
	}
	logger.Info("✅ Application restarted")

	// Wait for app to stabilize
	logger.Info("Waiting for app to start...")
	time.Sleep(10 * time.Second)

	// ========================================
	// EVALUATE: Verify the changes
	// ========================================
	logger.Info("")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("🧪 VERIFICATION")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Test virtual key works
	logger.Info("1. Testing virtual key authentication")
	if err := verifyVirtualKey(rc.Ctx, newVKey); err != nil {
		logger.Error("❌ Virtual key authentication failed", zap.Error(err))
	} else {
		logger.Info("✅ Virtual key authentication works")
		// Show available models
		if err := showAvailableModels(rc.Ctx, newVKey); err != nil {
			logger.Warn("Could not list models", zap.Error(err))
		}
	}

	// Verify database
	logger.Info("")
	logger.Info("2. Verifying database configuration")
	if err := verifyDatabase(rc.Ctx, newVKey); err != nil {
		logger.Warn("⚠️  Database verification warning", zap.Error(err))
	} else {
		logger.Info("✅ Database has correct key")
	}

	// ========================================
	// Summary
	// ========================================
	logger.Info("")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("✅ API KEY ROTATION COMPLETE")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("")
	logger.Info("🔑 New Virtual Key:", zap.String("key", sanitizeKey(newVKey)))
	logger.Info("")
	logger.Info("🤖 Authorized Models:")
	logger.Info("   • Moni (GPT-5-mini)")
	logger.Info("   • Moni-4.1 (GPT-4.1-mini)")
	logger.Info("   • Moni-o3 (o3-mini)")
	logger.Info("   • nomic-embed-text (Ollama)")
	logger.Info("")
	logger.Info("🧪 Test in Moni UI: http://localhost:8513")
	logger.Info("")

	return nil
}

// loadEnvironment loads the master key and current virtual key from .env file
func loadEnvironment(ctx context.Context, envFile string) (masterKey, currentVKey string, err error) {
	logger := otelzap.Ctx(ctx)

	file, err := os.Open(envFile)
	if err != nil {
		return "", "", fmt.Errorf("failed to open .env file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"'")

		switch key {
		case "LITELLM_MASTER_KEY":
			masterKey = value
		case "OPENAI_API_KEY":
			currentVKey = value
		}
	}

	if err := scanner.Err(); err != nil {
		return "", "", fmt.Errorf("failed to read .env file: %w", err)
	}

	if masterKey == "" {
		return "", "", fmt.Errorf("LITELLM_MASTER_KEY not found in .env file")
	}

	logger.Debug("Environment loaded",
		zap.String("env_file", envFile),
		zap.Bool("has_master_key", masterKey != ""),
		zap.Bool("has_current_vkey", currentVKey != ""))

	return masterKey, currentVKey, nil
}

// checkDatabase verifies PostgreSQL is accessible
func checkDatabase(ctx context.Context) error {
	cmd := exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerPostgres,
		"pg_isready", "-U", bionicgpt.DefaultPostgresUser)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("PostgreSQL is not ready: %w", err)
	}

	return nil
}

// checkLiteLLM verifies LiteLLM proxy is accessible
func checkLiteLLM(ctx context.Context) error {
	cmd := exec.CommandContext(ctx,
		"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
		"http://localhost:4000/health/readiness")

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("LiteLLM health check failed: %w", err)
	}

	statusCode := strings.TrimSpace(string(output))
	if statusCode != "200" {
		return fmt.Errorf("LiteLLM returned HTTP %s", statusCode)
	}

	return nil
}

// showCurrentModels displays the current models in the database
func showCurrentModels(ctx context.Context) error {
	cmd := exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerPostgres,
		"psql", "-U", bionicgpt.DefaultPostgresUser, "-d", bionicgpt.DefaultPostgresDB,
		"-c", "SELECT id, name, SUBSTRING(api_key, 1, 15) || '...' as key FROM models ORDER BY id;")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to query models: %w", err)
	}

	fmt.Println(string(output))
	return nil
}

// deleteVirtualKey deletes an existing virtual key from LiteLLM
func deleteVirtualKey(ctx context.Context, masterKey, vKey string) error {
	payload := fmt.Sprintf(`{"keys": ["%s"]}`, vKey)

	cmd := exec.CommandContext(ctx,
		"curl", "-s", "-X", "POST", "http://localhost:4000/key/delete",
		"-H", fmt.Sprintf("Authorization: Bearer %s", masterKey),
		"-H", "Content-Type: application/json",
		"-d", payload)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete key: %s: %w", string(output), err)
	}

	return nil
}

// generateVirtualKey generates a new virtual key with all models
func generateVirtualKey(ctx context.Context, masterKey string) (string, error) {
	logger := otelzap.Ctx(ctx)

	currentDate := time.Now().Format("2006-01-02")

	payload := fmt.Sprintf(`{
		"models": ["Moni", "Moni-4.1", "Moni-o3", "nomic-embed-text"],
		"duration": null,
		"key_alias": "moni-application",
		"metadata": {
			"purpose": "Moni application - all models with search",
			"created_by": "eos",
			"created_date": "%s"
		}
	}`, currentDate)

	cmd := exec.CommandContext(ctx,
		"curl", "-s", "-X", "POST", "http://localhost:4000/key/generate",
		"-H", fmt.Sprintf("Authorization: Bearer %s", masterKey),
		"-H", "Content-Type: application/json",
		"-d", payload)

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}

	var response keyGenerateResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if response.Key == "" {
		return "", fmt.Errorf("no key in response: %s", string(output))
	}

	logger.Debug("Virtual key generated",
		zap.String("key_name", response.KeyName),
		zap.Strings("models", response.Models))

	return response.Key, nil
}

// updateEnvFile updates the .env file with the new virtual key
func updateEnvFile(ctx context.Context, envFile, newVKey string) error {
	logger := otelzap.Ctx(ctx)

	// Create backup
	backupFile := envFile + ".backup." + time.Now().Format("20060102_150405")
	input, err := os.ReadFile(envFile)
	if err != nil {
		return fmt.Errorf("failed to read .env file: %w", err)
	}

	if err := os.WriteFile(backupFile, input, 0600); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	logger.Debug("Created .env backup", zap.String("backup", backupFile))

	// Read and update
	lines := strings.Split(string(input), "\n")
	var updated []string

	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "OPENAI_API_KEY=") {
			updated = append(updated, fmt.Sprintf("OPENAI_API_KEY=%s", newVKey))
		} else if strings.HasPrefix(strings.TrimSpace(line), "EMBEDDINGS_API_KEY=") {
			updated = append(updated, fmt.Sprintf("EMBEDDINGS_API_KEY=%s", newVKey))
		} else {
			updated = append(updated, line)
		}
	}

	// Write updated content
	content := strings.Join(updated, "\n")
	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write .env file: %w", err)
	}

	logger.Debug(".env file updated")
	return nil
}

// updateDatabaseKeys updates all model API keys in the database
func updateDatabaseKeys(ctx context.Context, newVKey string) error {
	logger := otelzap.Ctx(ctx)

	// Update all models with the new key
	sql := fmt.Sprintf("BEGIN; UPDATE models SET api_key = '%s'; COMMIT;", newVKey)

	cmd := exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerPostgres,
		"psql", "-U", bionicgpt.DefaultPostgresUser, "-d", bionicgpt.DefaultPostgresDB,
		"-c", sql)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update database: %s: %w", string(output), err)
	}

	// Show updated state
	showCmd := exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerPostgres,
		"psql", "-U", bionicgpt.DefaultPostgresUser, "-d", bionicgpt.DefaultPostgresDB,
		"-c", "SELECT id, name, SUBSTRING(api_key, 1, 15) || '...' as updated_key FROM models ORDER BY id;")

	showOutput, _ := showCmd.Output()
	logger.Debug("Updated database models",
		zap.String("result", string(showOutput)))

	return nil
}

// restartApp restarts the Moni application container
func restartApp(ctx context.Context, installDir string) error {
	logger := otelzap.Ctx(ctx)

	// Force recreate the app container to pick up new .env
	cmd := exec.CommandContext(ctx,
		"docker", "compose", "-f", filepath.Join(installDir, "docker-compose.yml"),
		"rm", "-sf", bionicgpt.ServiceApp)

	if output, err := cmd.CombinedOutput(); err != nil {
		logger.Debug("docker compose rm output", zap.String("output", string(output)))
		// Continue even if rm fails (container might not exist)
	}

	// Start app
	upCmd := exec.CommandContext(ctx,
		"docker", "compose", "-f", filepath.Join(installDir, "docker-compose.yml"),
		"up", "-d", bionicgpt.ServiceApp)

	if output, err := upCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start app: %s: %w", string(output), err)
	}

	logger.Debug("App container recreated")
	return nil
}

// verifyVirtualKey tests that the virtual key works
func verifyVirtualKey(ctx context.Context, vKey string) error {
	cmd := exec.CommandContext(ctx,
		"curl", "-s", "-w", "%{http_code}", "-o", "/dev/null",
		"-H", fmt.Sprintf("Authorization: Bearer %s", vKey),
		"http://localhost:4000/v1/models")

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("virtual key test failed: %w", err)
	}

	statusCode := strings.TrimSpace(string(output))
	if statusCode != "200" {
		return fmt.Errorf("virtual key returned HTTP %s", statusCode)
	}

	return nil
}

// showAvailableModels lists models accessible with the virtual key
func showAvailableModels(ctx context.Context, vKey string) error {
	logger := otelzap.Ctx(ctx)

	cmd := exec.CommandContext(ctx,
		"curl", "-s",
		"-H", fmt.Sprintf("Authorization: Bearer %s", vKey),
		"http://localhost:4000/v1/models")

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list models: %w", err)
	}

	var response modelsListResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return fmt.Errorf("failed to parse models response: %w", err)
	}

	logger.Info("Available models:")
	for _, model := range response.Data {
		logger.Info(fmt.Sprintf("   • %s", model.ID))
	}

	return nil
}

// verifyDatabase checks that the database has the correct key
func verifyDatabase(ctx context.Context, expectedKey string) error {
	logger := otelzap.Ctx(ctx)

	// Count total models
	totalCmd := exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerPostgres,
		"psql", "-U", bionicgpt.DefaultPostgresUser, "-d", bionicgpt.DefaultPostgresDB,
		"-t", "-c", "SELECT COUNT(*) FROM models;")

	totalOutput, err := totalCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to count models: %w", err)
	}

	totalCount := strings.TrimSpace(string(totalOutput))

	// Count models with new key
	countCmd := exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerPostgres,
		"psql", "-U", bionicgpt.DefaultPostgresUser, "-d", bionicgpt.DefaultPostgresDB,
		"-t", "-c", fmt.Sprintf("SELECT COUNT(*) FROM models WHERE api_key = '%s';", expectedKey))

	countOutput, err := countCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to verify key: %w", err)
	}

	updatedCount := strings.TrimSpace(string(countOutput))

	logger.Info("Database verification",
		zap.String("total_models", totalCount),
		zap.String("updated_models", updatedCount))

	if totalCount != updatedCount {
		return fmt.Errorf("some models may not have been updated (total: %s, updated: %s)", totalCount, updatedCount)
	}

	return nil
}

// sanitizeKey returns a safe version of the key for logging
// Shows only the first 20 characters
func sanitizeKey(key string) string {
	if len(key) <= 20 {
		return key[:4] + "..."
	}
	return key[:20] + "..."
}
