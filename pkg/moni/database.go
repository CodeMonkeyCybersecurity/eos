package moni

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
	"go.uber.org/zap/otelzap"
)

// ConfigureDatabase configures database models and prompts
// THIS IS WHERE llama3 → Moni RENAMING HAPPENS
func ConfigureDatabase(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Phase 5: Database Configuration")

	// Step 1: Upsert models (3 models)
	modelsSQL := fmt.Sprintf(`
INSERT INTO models (id, model_type, name, base_url, context_size, tpm_limit, rpm_limit, api_key)
VALUES
  (1, 'Embeddings', 'nomic-embed-text', 'http://litellm-proxy:4000', %d, %d, %d, 'PLACEHOLDER'),
  (2, 'LLM', 'Moni', 'http://litellm-proxy:4000', %d, %d, %d, 'PLACEHOLDER'),
  (3, 'LLM', 'Moni-4.1', 'http://litellm-proxy:4000', %d, %d, %d, 'PLACEHOLDER')
ON CONFLICT (id) DO UPDATE SET
  model_type = EXCLUDED.model_type,
  name = EXCLUDED.name,
  base_url = EXCLUDED.base_url,
  context_size = EXCLUDED.context_size,
  tpm_limit = EXCLUDED.tpm_limit,
  rpm_limit = EXCLUDED.rpm_limit,
  api_key = EXCLUDED.api_key;
`, EmbeddingsContextSize, EmbeddingsTPMLimit, EmbeddingsRPMLimit,
		ModelContextSize, ModelTPMLimit, ModelRPMLimit,
		ModelContextSize, ModelFallbackTPMLimit, ModelFallbackRPMLimit)

	logger.Info("Upserting models",
		zap.String("model_1", "nomic-embed-text (Embeddings, 8192 context)"),
		zap.String("model_2", "Moni (LLM, GPT-5-mini, 16384 max output tokens)"),
		zap.String("model_3", "Moni-4.1 (LLM, GPT-4.1-mini, 16384 max output tokens)"))

	if err := executeSQL(rc, modelsSQL, "Upsert models"); err != nil {
		return err
	}

	// Step 2: Update prompt name from llama3 to Moni
	// THIS IS THE KEY RENAMING OPERATION
	promptSQL := `
UPDATE prompts
SET name = 'Moni',
    description = 'Moni AI Assistant powered by GPT-5-mini',
    updated_at = now()
WHERE name = 'llama3' OR id = 1;
`

	logger.Info("Renaming default assistant: llama3 → Moni")
	if err := executeSQL(rc, promptSQL, "Update prompt name"); err != nil {
		return err
	}

	// Step 3: Link Moni prompt to Moni model
	linkSQL := `
UPDATE prompts
SET model_id = 2,
    updated_at = now()
WHERE name = 'Moni';
`

	logger.Info("Linking Moni assistant to Moni model (ID 2)")
	if err := executeSQL(rc, linkSQL, "Link prompt to model"); err != nil {
		return err
	}

	logger.Info("Database configuration complete")
	return nil
}

// ApplyDatabaseSecurity applies database security hardening
func ApplyDatabaseSecurity(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Phase 7: Database Security Hardening")

	// Get postgres password from .env
	envVars, err := readEnvFile(MoniEnvFile)
	if err != nil {
		return fmt.Errorf("failed to read .env file: %w", err)
	}

	postgresPassword, ok := envVars["POSTGRES_PASSWORD"]
	if !ok || postgresPassword == "" {
		return fmt.Errorf("POSTGRES_PASSWORD not found in .env")
	}

	// Step 1: Harden LiteLLM database
	logger.Info("Hardening LiteLLM database",
		zap.String("action", "removing superuser privileges"),
		zap.String("restriction", "DML only (no DDL)"))

	litellmSQL := `
ALTER USER litellm NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT CONNECT ON DATABASE litellm TO litellm;
GRANT USAGE ON SCHEMA public TO litellm;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO litellm;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO litellm;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO litellm;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO litellm;
`

	if err := executeSQLInContainer(rc, LiteLLMDBContainer, "litellm", "litellm", litellmSQL); err != nil {
		return fmt.Errorf("failed to harden LiteLLM database: %w", err)
	}

	logger.Info("LiteLLM database hardened")

	// Step 2: Harden BionicGPT database
	logger.Info("Hardening BionicGPT database",
		zap.String("action", "creating bionic_readonly user"),
		zap.String("restriction", "bionic_application to DML only"),
		zap.String("privileges", "default privileges configured"))

	// Escape single quotes in password
	escapedPassword := strings.ReplaceAll(postgresPassword, "'", "''")

	bionicSQL := fmt.Sprintf(`
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = 'bionic_readonly') THEN
        CREATE USER bionic_readonly WITH PASSWORD '%s';
    END IF;
END $$;

REVOKE ALL ON DATABASE "bionic-gpt" FROM bionic_application;
REVOKE ALL ON SCHEMA public FROM bionic_application;

GRANT CONNECT ON DATABASE "bionic-gpt" TO bionic_application;
GRANT USAGE ON SCHEMA public TO bionic_application;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO bionic_application;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO bionic_application;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO bionic_application;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO bionic_application;

GRANT CONNECT ON DATABASE "bionic-gpt" TO bionic_readonly;
GRANT USAGE ON SCHEMA public TO bionic_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO bionic_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    GRANT SELECT ON TABLES TO bionic_readonly;
`, escapedPassword)

	if err := executeSQLInContainer(rc, PostgresContainer, "postgres", DBName, bionicSQL); err != nil {
		return fmt.Errorf("failed to harden BionicGPT database: %w", err)
	}

	logger.Info("BionicGPT database hardened")

	logger.Info("Database Security Hardening Complete",
		zap.String("litellm", "No superuser, DML only"),
		zap.String("bionic_application", "DML only (no schema changes)"),
		zap.String("bionic_readonly", "Created for monitoring (read-only)"),
		zap.String("benefits", "Prevents privilege escalation, limits blast radius"))

	return nil
}

// EnableRowLevelSecurity enables RLS for multi-tenant data isolation
func EnableRowLevelSecurity(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Enabling Row Level Security (Multi-Tenant Isolation)")

	// RLS SQL from enable_rls.sql
	rlsSQL := `
-- Enable RLS on tables with direct team_id
ALTER TABLE api_key_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_trail ENABLE ROW LEVEL SECURITY;
ALTER TABLE conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE datasets ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_pipelines ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth2_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE prompts ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_users ENABLE ROW LEVEL SECURITY;

-- Enable RLS on tables with indirect team_id (via foreign keys)
ALTER TABLE chats ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE chunks ENABLE ROW LEVEL SECURITY;

-- Create RLS policies for direct team_id tables
CREATE POLICY tenant_isolation_api_key_connections ON api_key_connections
    FOR ALL TO bionic_application
    USING (team_id = current_setting('app.current_team_id', true)::int);

CREATE POLICY tenant_isolation_api_keys ON api_keys
    FOR ALL TO bionic_application
    USING (team_id = current_setting('app.current_team_id', true)::int);

CREATE POLICY tenant_isolation_audit_trail ON audit_trail
    FOR ALL TO bionic_application
    USING (team_id = current_setting('app.current_team_id', true)::int);

CREATE POLICY tenant_isolation_conversations ON conversations
    FOR ALL TO bionic_application
    USING (team_id = current_setting('app.current_team_id', true)::int);

CREATE POLICY tenant_isolation_datasets ON datasets
    FOR ALL TO bionic_application
    USING (team_id = current_setting('app.current_team_id', true)::int);

CREATE POLICY tenant_isolation_document_pipelines ON document_pipelines
    FOR ALL TO bionic_application
    USING (team_id = current_setting('app.current_team_id', true)::int);

CREATE POLICY tenant_isolation_integrations ON integrations
    FOR ALL TO bionic_application
    USING (team_id = current_setting('app.current_team_id', true)::int);

CREATE POLICY tenant_isolation_invitations ON invitations
    FOR ALL TO bionic_application
    USING (team_id = current_setting('app.current_team_id', true)::int);

CREATE POLICY tenant_isolation_oauth2_connections ON oauth2_connections
    FOR ALL TO bionic_application
    USING (team_id = current_setting('app.current_team_id', true)::int);

CREATE POLICY tenant_isolation_objects ON objects
    FOR ALL TO bionic_application
    USING (team_id = current_setting('app.current_team_id', true)::int);

CREATE POLICY tenant_isolation_prompts ON prompts
    FOR ALL TO bionic_application
    USING (team_id = current_setting('app.current_team_id', true)::int);

CREATE POLICY tenant_isolation_team_users ON team_users
    FOR ALL TO bionic_application
    USING (team_id = current_setting('app.current_team_id', true)::int);

-- Create RLS policies for indirect team_id tables
CREATE POLICY tenant_isolation_chats ON chats
    FOR ALL TO bionic_application
    USING (
        conversation_id IN (
            SELECT id FROM conversations
            WHERE team_id = current_setting('app.current_team_id', true)::int
        )
    );

CREATE POLICY tenant_isolation_documents ON documents
    FOR ALL TO bionic_application
    USING (
        dataset_id IN (
            SELECT id FROM datasets
            WHERE team_id = current_setting('app.current_team_id', true)::int
        )
    );

CREATE POLICY tenant_isolation_chunks ON chunks
    FOR ALL TO bionic_application
    USING (
        document_id IN (
            SELECT d.id FROM documents d
            JOIN datasets ds ON d.dataset_id = ds.id
            WHERE ds.team_id = current_setting('app.current_team_id', true)::int
        )
    );
`

	logger.Info("Enabling RLS on 15 critical tables",
		zap.Int("direct_team_id", 12),
		zap.Int("indirect_team_id", 3))

	if err := executeSQLInContainer(rc, PostgresContainer, "postgres", DBName, rlsSQL); err != nil {
		return fmt.Errorf("failed to enable RLS: %w", err)
	}

	logger.Info("RLS enabled on all tables",
		zap.Int("tables", 15),
		zap.Int("policies", 15))

	// Verify RLS enabled
	verifySQL := `
SELECT COUNT(*) FROM pg_tables
WHERE schemaname = 'public' AND rowsecurity = true;
`

	count, err := querySingleValue(rc, PostgresContainer, DBUser, DBName, verifySQL)
	if err != nil {
		logger.Warn("Could not verify RLS count", zap.Error(err))
	} else {
		logger.Info("RLS verification complete", zap.String("tables_with_rls", count))
	}

	logger.Info("Row Level Security Enabled",
		zap.Int("protected_tables", 15),
		zap.String("isolation", "database-level tenant isolation enforced"),
		zap.String("security", "application bypasses cannot leak cross-tenant data"))

	logger.Warn("CRITICAL: Application must set session variable: SET app.current_team_id = <user's team ID>")

	return nil
}

// executeSQL executes SQL in the PostgreSQL container
func executeSQL(rc *eos_io.RuntimeContext, sql, description string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Executing SQL", zap.String("operation", description))

	return executeSQLInContainer(rc, PostgresContainer, DBUser, DBName, sql)
}

// executeSQLInContainer executes SQL in a specific container
func executeSQLInContainer(rc *eos_io.RuntimeContext, container, user, database, sql string) error {
	ctx, cancel := context.WithTimeout(rc.Ctx, CommandTimeout)
	defer cancel()

	// Use -c for single commands, or pipe for multi-line SQL
	var output string
	var err error

	if strings.Contains(sql, "\n") {
		// Multi-line SQL - use stdin
		cmd := exec.CommandContext(ctx, "docker", "exec", "-i", container,
			"psql", "-U", user, "-d", database)
		cmd.Stdin = strings.NewReader(sql)

		out, execErr := cmd.CombinedOutput()
		output = string(out)
		err = execErr
	} else {
		// Single line SQL - use -c
		output, err = execute.Run(ctx, execute.Options{
			Command: "docker",
			Args:    []string{"exec", container, "psql", "-U", user, "-d", database, "-c", sql},
			Capture: true,
		})
	}

	if err != nil {
		return fmt.Errorf("SQL execution failed: %s: %w", output, err)
	}

	return nil
}

// querySingleValue queries a single value from the database
func querySingleValue(rc *eos_io.RuntimeContext, container, user, database, sql string) (string, error) {
	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"exec", container, "psql", "-U", user, "-d", database, "-t", "-c", sql},
		Capture: true,
	})

	if err != nil {
		return "", err
	}

	return strings.TrimSpace(output), nil
}
