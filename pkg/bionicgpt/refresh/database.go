// Package refresh - Database operations for Moni refresh
package refresh

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// updateDatabase updates the database models configuration
// CRITICAL: Uses DELETE + INSERT pattern (UPDATE silently fails)
// CRITICAL: Must pipe SQL via docker exec -i < file.sql (heredoc doesn't work)
func (r *Refresher) updateDatabase(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Step 1: Get team ID from database
	teamID, err := r.getTeamID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get team ID: %w", err)
	}
	logger.Info("Retrieved team ID from database", zap.Int("team_id", teamID))

	// Step 2: Generate SQL from template
	sqlContent, err := r.generateModelUpdateSQL(teamID)
	if err != nil {
		return fmt.Errorf("failed to generate SQL: %w", err)
	}

	// Step 3: Write SQL to temporary file
	tmpFile := filepath.Join(os.TempDir(), "moni-update-models.sql")
	if err := os.WriteFile(tmpFile, []byte(sqlContent), shared.SecretFilePerm); err != nil {
		return fmt.Errorf("failed to write SQL file: %w", err)
	}
	defer os.Remove(tmpFile)

	logger.Debug("Generated SQL file", zap.String("path", tmpFile))

	// Step 4: Execute SQL via pipe (THE ONLY WAY THAT WORKS)
	// RATIONALE: docker exec with heredoc or -c doesn't actually execute the SQL
	//            Only piping from stdin works reliably
	if err := r.executeSQLFile(ctx, bionicgpt.ContainerNamePostgres, bionicgpt.DefaultPostgresUser, bionicgpt.DefaultPostgresDB, tmpFile); err != nil {
		return fmt.Errorf("failed to execute SQL: %w", err)
	}

	// Step 5: Verify the update
	if err := r.verifyModelsUpdate(ctx); err != nil {
		return fmt.Errorf("database update verification failed: %w", err)
	}

	logger.Info("Database models updated successfully")
	return nil
}

// getTeamID retrieves the first team ID from the database
func (r *Refresher) getTeamID(ctx context.Context) (int, error) {
	logger := otelzap.Ctx(ctx)

	cmd := exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerNamePostgres,
		"psql", "-U", bionicgpt.DefaultPostgresUser, "-d", bionicgpt.DefaultPostgresDB,
		"-t", "-c", "SELECT id FROM teams LIMIT 1;")

	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to query team ID: %w", err)
	}

	var teamID int
	trimmed := strings.TrimSpace(string(output))
	if _, err := fmt.Sscanf(trimmed, "%d", &teamID); err != nil {
		logger.Error("Failed to parse team ID",
			zap.String("output", trimmed),
			zap.Error(err))
		return 0, fmt.Errorf("failed to parse team ID from output '%s': %w", trimmed, err)
	}

	return teamID, nil
}

// generateModelUpdateSQL generates SQL to update models configuration
// CRITICAL: Uses DELETE + INSERT pattern (UPDATE doesn't work)
// SECURITY: All values are constants or validated integers (no SQL injection risk)
func (r *Refresher) generateModelUpdateSQL(teamID int) (string, error) {
	sqlTemplate := `BEGIN;

-- Show before state
SELECT 'BEFORE:' as status, id, model_type::text as type, name, base_url FROM models ORDER BY id;

-- Delete existing (CASCADE to prompts)
DELETE FROM prompts WHERE model_id IN ({{.ModelIDEmbeddings}}, {{.ModelIDLLM}});
DELETE FROM models WHERE id IN ({{.ModelIDEmbeddings}}, {{.ModelIDLLM}});

-- Insert fresh models
INSERT INTO models (id, model_type, name, base_url, context_size, tpm_limit, rpm_limit)
VALUES
  ({{.ModelIDEmbeddings}}, '{{.ModelTypeEmbeddings}}', '{{.ModelNameEmbeddings}}', '{{.ModelBase}}', {{.ModelContextEmbeddings}}, {{.ModelTPMLimit}}, {{.ModelRPMLimit}}),
  ({{.ModelIDLLM}}, '{{.ModelTypeLLM}}', '{{.ModelNameLLM}}', '{{.ModelBase}}', {{.ModelContextLLM}}, {{.ModelLLMTPMLimit}}, {{.ModelLLMRPMLimit}});

-- Insert prompt with all required fields
-- RATIONALE: All fields are required by PostgreSQL NOT NULL constraints
-- SECURITY: Row-Level Security (RLS) enforced via team_id
INSERT INTO prompts (
  team_id, model_id, visibility, name,
  max_history_items, max_chunks, max_tokens, trim_ratio,
  temperature, created_by, prompt_type, category_id, description
)
VALUES (
  {{.TeamID}}, {{.ModelIDLLM}}, '{{.PromptVisibility}}', '{{.PromptName}}',
  {{.PromptMaxHistory}}, {{.PromptMaxChunks}}, {{.PromptMaxTokens}}, {{.PromptTrimRatio}},
  {{.PromptTemperature}}, {{.TeamID}}, '{{.PromptType}}', {{.PromptCategoryID}}, '{{.PromptDescription}}'
);

-- Show after state
SELECT 'AFTER:' as status, id, model_type::text as type, name, base_url FROM models ORDER BY id;

COMMIT;
`

	tmpl, err := template.New("sql").Parse(sqlTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse SQL template: %w", err)
	}

	data := map[string]interface{}{
		// Team ID (from database query)
		"TeamID": teamID,

		// Model IDs (constants)
		"ModelIDEmbeddings": bionicgpt.ModelIDEmbeddings,
		"ModelIDLLM":        bionicgpt.ModelIDLLM,

		// Model configuration (constants)
		"ModelTypeEmbeddings":    bionicgpt.ModelTypeEmbeddings,
		"ModelTypeLLM":           bionicgpt.ModelTypeLLM,
		"ModelNameEmbeddings":    bionicgpt.ModelNameEmbeddings,
		"ModelNameLLM":           bionicgpt.ModelNameLLM,
		"ModelBase":              bionicgpt.ModelBaseLiteLLM,
		"ModelContextEmbeddings": bionicgpt.ModelContextEmbeddings,
		"ModelContextLLM":        bionicgpt.ModelContextLLM,
		"ModelTPMLimit":          bionicgpt.ModelTPMLimit,
		"ModelRPMLimit":          bionicgpt.ModelRPMLimit,
		"ModelLLMTPMLimit":       bionicgpt.ModelLLMTPMLimit,
		"ModelLLMRPMLimit":       bionicgpt.ModelLLMRPMLimit,

		// Prompt configuration (constants)
		"PromptVisibility":  bionicgpt.PromptVisibility,
		"PromptName":        bionicgpt.PromptName,
		"PromptMaxHistory":  bionicgpt.PromptMaxHistory,
		"PromptMaxChunks":   bionicgpt.PromptMaxChunks,
		"PromptMaxTokens":   bionicgpt.PromptMaxTokens,
		"PromptTrimRatio":   bionicgpt.PromptTrimRatio,
		"PromptTemperature": bionicgpt.PromptTemperature,
		"PromptType":        bionicgpt.PromptType,
		"PromptCategoryID":  bionicgpt.PromptCategoryID,
		"PromptDescription": bionicgpt.PromptDescription,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute SQL template: %w", err)
	}

	return buf.String(), nil
}

// executeSQLFile executes a SQL file via docker exec -i < file
// CRITICAL: This is THE ONLY reliable way to execute multi-statement SQL
// RATIONALE: docker exec with -c or heredoc doesn't actually execute the statements
func (r *Refresher) executeSQLFile(ctx context.Context, containerName, user, database, sqlFilePath string) error {
	logger := otelzap.Ctx(ctx)

	// Open SQL file for reading
	sqlFile, err := os.Open(sqlFilePath)
	if err != nil {
		return fmt.Errorf("failed to open SQL file: %w", err)
	}
	defer sqlFile.Close()

	// Create command with stdin pipe
	cmd := exec.CommandContext(ctx,
		"docker", "exec", "-i", containerName,
		"psql", "-U", user, "-d", database)

	cmd.Stdin = sqlFile

	// Capture output for verification
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("SQL execution failed",
			zap.String("container", containerName),
			zap.String("database", database),
			zap.String("output", string(output)),
			zap.Error(err))
		return fmt.Errorf("SQL execution failed: %s: %w", string(output), err)
	}

	// Verify transaction committed
	if !strings.Contains(string(output), "COMMIT") {
		logger.Error("Transaction did not commit",
			zap.String("output", string(output)))
		return fmt.Errorf("transaction did not commit - check SQL output")
	}

	logger.Debug("SQL executed successfully",
		zap.String("container", containerName),
		zap.String("database", database))

	return nil
}

// verifyModelsUpdate verifies the models were updated correctly
func (r *Refresher) verifyModelsUpdate(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	cmd := exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerNamePostgres,
		"psql", "-U", bionicgpt.DefaultPostgresUser, "-d", bionicgpt.DefaultPostgresDB,
		"-t", "-c", fmt.Sprintf("SELECT COUNT(*) FROM models WHERE name IN ('%s', '%s');",
			bionicgpt.ModelNameMoni, bionicgpt.ModelNameEmbeddings))

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to verify models: %w", err)
	}

	count := strings.TrimSpace(string(output))
	if count != "2" {
		logger.Error("Model verification failed",
			zap.String("expected_count", "2"),
			zap.String("actual_count", count))
		return fmt.Errorf("expected 2 models, found %s", count)
	}

	logger.Info("Models verified successfully", zap.String("count", count))
	return nil
}

// clearCaches clears LiteLLM verification token cache
// CRITICAL: Without this, old API keys persist even after environment variable changes
// RATIONALE: LiteLLM caches verification tokens in database for performance
func (r *Refresher) clearCaches(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Clear LiteLLM verification tokens
	cmd := exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerNameLiteLLMDB,
		"psql", "-U", bionicgpt.LiteLLMDefaultUser, "-d", bionicgpt.LiteLLMDefaultDB,
		"-c", fmt.Sprintf(`DELETE FROM "%s";`, bionicgpt.LiteLLMVerificationTokenTable))

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to clear LiteLLM cache",
			zap.String("output", string(output)),
			zap.Error(err))
		return fmt.Errorf("failed to clear LiteLLM cache: %s: %w", string(output), err)
	}

	// Verify deletion
	cmd = exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerNameLiteLLMDB,
		"psql", "-U", bionicgpt.LiteLLMDefaultUser, "-d", bionicgpt.LiteLLMDefaultDB,
		"-t", "-c", fmt.Sprintf(`SELECT COUNT(*) FROM "%s";`, bionicgpt.LiteLLMVerificationTokenTable))

	output, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to verify cache clear: %w", err)
	}

	count := strings.TrimSpace(string(output))
	if count != "0" {
		logger.Warn("Cache clear verification failed",
			zap.String("expected_count", "0"),
			zap.String("actual_count", count))
		return fmt.Errorf("cache not fully cleared (count: %s)", count)
	}

	logger.Info("LiteLLM cache cleared successfully")
	return nil
}
