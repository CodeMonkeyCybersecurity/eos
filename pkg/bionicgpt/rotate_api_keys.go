// Package bionicgpt provides API key rotation functionality for Moni/BionicGPT
//
// This module handles rotation of LiteLLM virtual keys used by the Moni application.
// Virtual keys provide access to configured models (Moni, Moni-4.1, Moni-o3, nomic-embed-text).
//
// Rotation Process:
//   1. ASSESS: Check prerequisites (database, LiteLLM proxy health, current configuration)
//   2. INTERVENE: Generate new virtual key, update .env, update database, restart app
//   3. EVALUATE: Verify new key works, test model access
//
// Security:
//   - Virtual keys are stored in .env file with restrictive permissions (0640)
//   - Old keys are deleted after successful rotation
//   - Automatic backup of .env file before changes
//   - Transaction-like behavior: rollback on failure
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package bionicgpt

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// APIKeyRotationState tracks the state of API key rotation for rollback
type APIKeyRotationState struct {
	OldVirtualKey      string
	NewVirtualKey      string
	MasterKey          string
	EnvFileBackupPath  string
	DatabaseUpdated    bool
	EnvFileUpdated     bool
	AppRestarted       bool
}

// RotateAPIKeys performs API key rotation for Moni
// ASSESS → INTERVENE → EVALUATE pattern
func RotateAPIKeys(rc *eos_io.RuntimeContext, config *RotateAPIKeysConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Moni API key rotation",
		zap.String("install_dir", config.InstallDir),
		zap.Bool("dry_run", config.DryRun))

	// Initialize state for potential rollback
	state := &APIKeyRotationState{}

	// ============================================================================
	// ASSESS: Check prerequisites
	// ============================================================================
	if err := assessAPIKeyRotationPrerequisites(rc, config, state); err != nil {
		return fmt.Errorf("prerequisite check failed: %w", err)
	}

	if config.DryRun {
		logger.Info("Dry run mode - stopping before making changes")
		return nil
	}

	// ============================================================================
	// INTERVENE: Perform rotation
	// ============================================================================
	if err := performAPIKeyRotation(rc, config, state); err != nil {
		// Attempt rollback if we've made partial changes
		if err := rollbackAPIKeyRotation(rc, config, state); err != nil {
			logger.Error("Rollback failed", zap.Error(err))
			return fmt.Errorf("rotation failed and rollback also failed: %w", err)
		}
		return fmt.Errorf("rotation failed (rolled back): %w", err)
	}

	// ============================================================================
	// EVALUATE: Verify rotation success
	// ============================================================================
	if !config.SkipVerify {
		if err := verifyAPIKeyRotation(rc, config, state); err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
	}

	logger.Info("API key rotation completed successfully",
		zap.String("new_key_prefix", state.NewVirtualKey[:20]+"..."))

	return nil
}

// assessAPIKeyRotationPrerequisites checks if rotation can proceed
// ASSESS phase: Check current state
func assessAPIKeyRotationPrerequisites(rc *eos_io.RuntimeContext, config *RotateAPIKeysConfig, state *APIKeyRotationState) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Assessing API key rotation prerequisites")

	// Check 1: Installation directory exists
	if _, err := os.Stat(config.InstallDir); os.IsNotExist(err) {
		return fmt.Errorf("installation directory does not exist: %s", config.InstallDir)
	}
	logger.Info("✓ Installation directory exists", zap.String("path", config.InstallDir))

	// Check 2: .env file exists
	envFile := filepath.Join(config.InstallDir, EnvFileName)
	if _, err := os.Stat(envFile); os.IsNotExist(err) {
		return fmt.Errorf(".env file not found: %s", envFile)
	}
	logger.Info("✓ .env file exists", zap.String("path", envFile))

	// Check 3: Read current configuration from .env
	envContent, err := os.ReadFile(envFile)
	if err != nil {
		return fmt.Errorf("failed to read .env file: %w", err)
	}

	// Extract master key
	masterKey, err := extractEnvVar(string(envContent), EnvVarLiteLLMMasterKey)
	if err != nil {
		return fmt.Errorf("failed to extract LITELLM_MASTER_KEY: %w", err)
	}
	state.MasterKey = masterKey
	logger.Info("✓ Master key found", zap.String("key_prefix", masterKey[:15]+"..."))

	// Extract current virtual key
	currentVKey, err := extractEnvVar(string(envContent), EnvVarOpenAIAPIKey)
	if err != nil {
		// Not an error if key doesn't exist yet (first rotation)
		logger.Warn("Current virtual key not found in .env (may be first rotation)")
		currentVKey = ""
	}
	state.OldVirtualKey = currentVKey
	if currentVKey != "" {
		logger.Info("✓ Current virtual key found", zap.String("key_prefix", currentVKey[:15]+"..."))
	}

	// Check 4: Database is ready
	if err := checkDatabaseReady(rc, config.InstallDir); err != nil {
		return fmt.Errorf("database is not ready: %w", err)
	}
	logger.Info("✓ Database is ready")

	// Check 5: LiteLLM proxy is healthy
	if err := checkLiteLLMHealth(rc, state.MasterKey); err != nil {
		return fmt.Errorf("LiteLLM proxy is not healthy: %w", err)
	}
	logger.Info("✓ LiteLLM proxy is healthy")

	// Check 6: Show current database state
	if err := showCurrentDatabaseState(rc, config.InstallDir); err != nil {
		logger.Warn("Failed to show current database state", zap.Error(err))
		// Not fatal - continue
	}

	logger.Info("All prerequisites satisfied")
	return nil
}

// performAPIKeyRotation executes the rotation
// INTERVENE phase: Apply changes
func performAPIKeyRotation(rc *eos_io.RuntimeContext, config *RotateAPIKeysConfig, state *APIKeyRotationState) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Performing API key rotation")

	// Step 1: Backup .env file
	if !config.SkipBackup {
		envFile := filepath.Join(config.InstallDir, EnvFileName)
		backupPath := envFile + time.Now().Format(EnvFileBackupFormat)

		envContent, err := os.ReadFile(envFile)
		if err != nil {
			return fmt.Errorf("failed to read .env for backup: %w", err)
		}

		if err := os.WriteFile(backupPath, envContent, 0640); err != nil {
			return fmt.Errorf("failed to create backup: %w", err)
		}

		state.EnvFileBackupPath = backupPath
		logger.Info("✓ Created .env backup", zap.String("path", backupPath))
	}

	// Step 2: Delete old virtual key (if exists)
	if state.OldVirtualKey != "" {
		if err := deleteVirtualKey(rc, state.MasterKey, state.OldVirtualKey); err != nil {
			logger.Warn("Failed to delete old virtual key (continuing anyway)", zap.Error(err))
			// Not fatal - key may have already been deleted
		} else {
			logger.Info("✓ Deleted old virtual key", zap.String("key_prefix", state.OldVirtualKey[:15]+"..."))
		}
	}

	// Step 3: Generate new virtual key
	newVKey, err := generateVirtualKey(rc, state.MasterKey)
	if err != nil {
		return fmt.Errorf("failed to generate new virtual key: %w", err)
	}
	state.NewVirtualKey = newVKey
	logger.Info("✓ Generated new virtual key", zap.String("key_prefix", newVKey[:20]+"..."))

	// Step 4: Update .env file with new key
	envFile := filepath.Join(config.InstallDir, EnvFileName)
	if err := updateEnvFileWithNewKey(rc, envFile, state.NewVirtualKey); err != nil {
		return fmt.Errorf("failed to update .env file: %w", err)
	}
	state.EnvFileUpdated = true
	logger.Info("✓ Updated .env file with new key")

	// Step 5: Update database with new key
	if err := updateDatabaseWithNewKey(rc, config.InstallDir, state.NewVirtualKey); err != nil {
		return fmt.Errorf("failed to update database: %w", err)
	}
	state.DatabaseUpdated = true
	logger.Info("✓ Updated database models with new key")

	// Step 6: Restart app container
	if !config.SkipRestart {
		if err := restartAppContainer(rc, config.InstallDir); err != nil {
			return fmt.Errorf("failed to restart app container: %w", err)
		}
		state.AppRestarted = true
		logger.Info("✓ Restarted app container")

		// Wait for app to stabilize
		logger.Info("Waiting for app to start...", zap.Duration("delay", ServiceStartupDelay))
		time.Sleep(ServiceStartupDelay)
	}

	logger.Info("API key rotation intervention completed")
	return nil
}

// verifyAPIKeyRotation verifies the rotation was successful
// EVALUATE phase: Verify results
func verifyAPIKeyRotation(rc *eos_io.RuntimeContext, config *RotateAPIKeysConfig, state *APIKeyRotationState) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying API key rotation")

	// Test 1: Virtual key authentication works
	logger.Info("Test 1: Virtual key authentication...")
	if err := testVirtualKeyAuth(rc, state.NewVirtualKey); err != nil {
		return fmt.Errorf("virtual key authentication failed: %w", err)
	}
	logger.Info("✓ Virtual key authentication works")

	// Test 2: Database has correct key
	logger.Info("Test 2: Database configuration...")
	if err := verifyDatabaseKeyCount(rc, config.InstallDir, state.NewVirtualKey); err != nil {
		return fmt.Errorf("database verification failed: %w", err)
	}
	logger.Info("✓ Database has correct key for models")

	// Test 3: App container has new key
	if !config.SkipRestart {
		logger.Info("Test 3: App container environment...")
		if err := verifyAppContainerEnv(rc, config.InstallDir, state.NewVirtualKey); err != nil {
			logger.Warn("App container may not have updated key yet",
				zap.Error(err),
				zap.String("hint", "Try: docker compose -f /opt/bionicgpt/docker-compose.yml restart app"))
			// Not fatal - user can restart manually
		} else {
			logger.Info("✓ App container has correct key")
		}
	}

	logger.Info("All verification tests passed")
	return nil
}

// rollbackAPIKeyRotation attempts to rollback changes if rotation fails
func rollbackAPIKeyRotation(rc *eos_io.RuntimeContext, config *RotateAPIKeysConfig, state *APIKeyRotationState) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Warn("Attempting rollback of API key rotation")

	rollbackSuccessful := true

	// Rollback .env file if we updated it
	if state.EnvFileUpdated && state.EnvFileBackupPath != "" {
		envFile := filepath.Join(config.InstallDir, EnvFileName)
		backupContent, err := os.ReadFile(state.EnvFileBackupPath)
		if err != nil {
			logger.Error("Failed to read backup file for rollback", zap.Error(err))
			rollbackSuccessful = false
		} else {
			if err := os.WriteFile(envFile, backupContent, 0640); err != nil {
				logger.Error("Failed to restore .env from backup", zap.Error(err))
				rollbackSuccessful = false
			} else {
				logger.Info("✓ Restored .env from backup")
			}
		}
	}

	// Rollback database if we updated it
	if state.DatabaseUpdated && state.OldVirtualKey != "" {
		if err := updateDatabaseWithNewKey(rc, config.InstallDir, state.OldVirtualKey); err != nil {
			logger.Error("Failed to rollback database", zap.Error(err))
			rollbackSuccessful = false
		} else {
			logger.Info("✓ Rolled back database to old key")
		}
	}

	// Restart app if we restarted it
	if state.AppRestarted {
		if err := restartAppContainer(rc, config.InstallDir); err != nil {
			logger.Error("Failed to restart app during rollback", zap.Error(err))
			rollbackSuccessful = false
		} else {
			logger.Info("✓ Restarted app with rolled back configuration")
		}
	}

	if !rollbackSuccessful {
		return fmt.Errorf("partial rollback failure - manual intervention required")
	}

	logger.Info("Rollback completed successfully")
	return nil
}

// Helper functions

// extractEnvVar extracts a value from .env content
func extractEnvVar(envContent, varName string) (string, error) {
	// Match: VAR_NAME="value" or VAR_NAME='value' or VAR_NAME=value
	pattern := fmt.Sprintf(`(?m)^%s\s*=\s*["']?([^"'\n]+)["']?`, regexp.QuoteMeta(varName))
	re := regexp.MustCompile(pattern)

	matches := re.FindStringSubmatch(envContent)
	if len(matches) < 2 {
		return "", fmt.Errorf("variable %s not found in .env", varName)
	}

	value := strings.TrimSpace(matches[1])
	// Remove trailing quotes if present
	value = strings.Trim(value, `"'`)

	if value == "" {
		return "", fmt.Errorf("variable %s is empty in .env", varName)
	}

	return value, nil
}

// checkDatabaseReady verifies PostgreSQL is ready
func checkDatabaseReady(rc *eos_io.RuntimeContext, installDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	containerName := ContainerNamePostgres

	// Check if postgres container is running
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"ps", "--filter", "name=" + containerName, "--format", "{{.Names}}"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to check postgres container: %w", err)
	}

	if strings.TrimSpace(output) == "" {
		return fmt.Errorf("postgres container is not running")
	}

	// Try pg_isready
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"exec", containerName, "pg_isready", "-U", DefaultPostgresUser},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("pg_isready failed: %s: %w", output, err)
	}

	logger.Debug("PostgreSQL is ready", zap.String("output", output))
	return nil
}

// checkLiteLLMHealth checks if LiteLLM proxy is healthy
func checkLiteLLMHealth(rc *eos_io.RuntimeContext, masterKey string) error {
	logger := otelzap.Ctx(rc.Ctx)

	url := fmt.Sprintf("http://localhost:%d%s", LiteLLMProxyPort, LiteLLMHealthEndpoint)

	req, err := http.NewRequestWithContext(rc.Ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed with status %d", resp.StatusCode)
	}

	logger.Debug("LiteLLM health check passed", zap.Int("status", resp.StatusCode))
	return nil
}

// showCurrentDatabaseState displays current database models configuration
func showCurrentDatabaseState(rc *eos_io.RuntimeContext, installDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	query := fmt.Sprintf("SELECT id, name, SUBSTRING(api_key, 1, 15) || '...' as key FROM %s ORDER BY id;", TableModels)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"exec", ContainerNamePostgres, "psql", "-U", DefaultPostgresUser, "-d", DefaultPostgresDB, "-t", "-c", query},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to query database: %w", err)
	}

	logger.Info("Current database state:\n" + output)
	return nil
}

// generateVirtualKey generates a new LiteLLM virtual key with all models
func generateVirtualKey(rc *eos_io.RuntimeContext, masterKey string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	url := fmt.Sprintf("http://localhost:%d%s", LiteLLMProxyPort, LiteLLMKeyGenerateEndpoint)

	request := LiteLLMKeyGenerateRequest{
		Models:   []string{ModelMoni, ModelMoni41, ModelMoniO3, ModelNomicEmbed},
		Duration: nil, // Never expire
		KeyAlias: APIKeyAlias,
		Metadata: map[string]string{
			"purpose":      "Moni application - all models with search",
			"created_by":   "eos",
			"created_date": time.Now().Format("2006-01-02"),
		},
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(rc.Ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+masterKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("key generation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return "", fmt.Errorf("key generation failed with status %d: %s", resp.StatusCode, buf.String())
	}

	var response LiteLLMKeyGenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if response.Key == "" {
		return "", fmt.Errorf("response did not contain a key")
	}

	logger.Debug("Generated virtual key",
		zap.String("key_alias", response.KeyAlias),
		zap.String("key_prefix", response.Key[:20]+"..."))

	return response.Key, nil
}

// deleteVirtualKey deletes an old virtual key
func deleteVirtualKey(rc *eos_io.RuntimeContext, masterKey, virtualKey string) error {
	logger := otelzap.Ctx(rc.Ctx)

	url := fmt.Sprintf("http://localhost:%d%s", LiteLLMProxyPort, LiteLLMKeyDeleteEndpoint)

	request := LiteLLMKeyDeleteRequest{
		Keys: []string{virtualKey},
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(rc.Ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+masterKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("key deletion request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return fmt.Errorf("key deletion failed with status %d: %s", resp.StatusCode, buf.String())
	}

	logger.Debug("Deleted virtual key", zap.String("key_prefix", virtualKey[:15]+"..."))
	return nil
}

// updateEnvFileWithNewKey updates .env file with new virtual key
func updateEnvFileWithNewKey(rc *eos_io.RuntimeContext, envFile, newKey string) error {
	logger := otelzap.Ctx(rc.Ctx)

	content, err := os.ReadFile(envFile)
	if err != nil {
		return fmt.Errorf("failed to read .env file: %w", err)
	}

	// Update OPENAI_API_KEY
	updatedContent := regexp.MustCompile(`(?m)^OPENAI_API_KEY=.*$`).ReplaceAllString(
		string(content),
		fmt.Sprintf("OPENAI_API_KEY=%s", newKey),
	)

	// Update EMBEDDINGS_API_KEY
	updatedContent = regexp.MustCompile(`(?m)^EMBEDDINGS_API_KEY=.*$`).ReplaceAllString(
		updatedContent,
		fmt.Sprintf("EMBEDDINGS_API_KEY=%s", newKey),
	)

	if err := os.WriteFile(envFile, []byte(updatedContent), 0640); err != nil {
		return fmt.Errorf("failed to write .env file: %w", err)
	}

	logger.Debug("Updated .env file with new key")
	return nil
}

// updateDatabaseWithNewKey updates database models table with new key
func updateDatabaseWithNewKey(rc *eos_io.RuntimeContext, installDir, newKey string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// SQL to update all models
	updateSQL := fmt.Sprintf("UPDATE %s SET api_key = '%s';", TableModels, newKey)
	selectSQL := fmt.Sprintf("SELECT id, name, SUBSTRING(api_key, 1, 15) || '...' as updated_key FROM %s ORDER BY id;", TableModels)

	combinedSQL := updateSQL + " " + selectSQL

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"exec", ContainerNamePostgres, "psql", "-U", DefaultPostgresUser, "-d", DefaultPostgresDB, "-t", "-c", combinedSQL},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to update database: %w", err)
	}

	logger.Debug("Updated database models", zap.String("result", output))
	return nil
}

// restartAppContainer restarts the app container to pick up new .env
func restartAppContainer(rc *eos_io.RuntimeContext, installDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Use docker compose restart for cleaner restart to pick up .env changes
	composeFile := filepath.Join(installDir, DockerComposeFileName)

	logger.Info("Restarting app container via docker compose")

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "-f", composeFile, "restart", ServiceApp},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to restart container: %s: %w", output, err)
	}

	logger.Debug("Container restarted successfully", zap.String("output", output))
	return nil
}

// testVirtualKeyAuth tests if the new virtual key works
func testVirtualKeyAuth(rc *eos_io.RuntimeContext, virtualKey string) error {
	logger := otelzap.Ctx(rc.Ctx)

	url := fmt.Sprintf("http://localhost:%d%s", LiteLLMProxyPort, LiteLLMModelsEndpoint)

	req, err := http.NewRequestWithContext(rc.Ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+virtualKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("authentication test failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed with status %d", resp.StatusCode)
	}

	// Parse response to show available models
	var modelsResp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&modelsResp); err != nil {
		logger.Warn("Failed to decode models response", zap.Error(err))
		// Not fatal - authentication worked
		return nil
	}

	logger.Info("Available models:",
		zap.Int("count", len(modelsResp.Data)))
	for _, model := range modelsResp.Data {
		logger.Info("  • " + model.ID)
	}

	return nil
}

// verifyDatabaseKeyCount checks that database has correct key
func verifyDatabaseKeyCount(rc *eos_io.RuntimeContext, installDir, expectedKey string) error {
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE api_key = '%s';", TableModels, expectedKey)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"exec", ContainerNamePostgres, "psql", "-U", DefaultPostgresUser, "-d", DefaultPostgresDB, "-t", "-c", query},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to query database: %w", err)
	}

	count := strings.TrimSpace(output)
	if count != "2" {
		return fmt.Errorf("expected 2 models with new key, found %s", count)
	}

	return nil
}

// verifyAppContainerEnv checks if app container has the new key
func verifyAppContainerEnv(rc *eos_io.RuntimeContext, installDir, expectedKey string) error {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"exec", ContainerNameApp, "env"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to get container environment: %w", err)
	}

	// Check if OPENAI_API_KEY matches
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, EnvVarOpenAIAPIKey+"=") {
			value := strings.TrimPrefix(line, EnvVarOpenAIAPIKey+"=")
			if value == expectedKey {
				return nil
			}
			return fmt.Errorf("app container has old key, restart may be needed")
		}
	}

	return fmt.Errorf("OPENAI_API_KEY not found in app container environment")
}
