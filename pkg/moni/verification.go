package moni

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
	"go.uber.org/zap/otelzap"
)

// WaitForService waits for a service to become ready
func WaitForService(rc *eos_io.RuntimeContext, name string, checkFunc func() bool, maxWait, checkInterval int) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Waiting for service", zap.String("service", name))

	elapsed := 0
	ticker := time.NewTicker(time.Duration(checkInterval) * time.Second)
	defer ticker.Stop()

	timeout := time.After(time.Duration(maxWait) * time.Second)

	for {
		select {
		case <-timeout:
			return fmt.Errorf("%s did not become ready within %ds", name, maxWait)

		case <-ticker.C:
			if checkFunc() {
				logger.Info("Service ready",
					zap.String("service", name),
					zap.Int("elapsed_seconds", elapsed))
				return nil
			}

			elapsed += checkInterval
			if elapsed%10 == 0 && elapsed < maxWait {
				logger.Info("Still waiting for service",
					zap.String("service", name),
					zap.Int("elapsed", elapsed))
			}
		}
	}
}

// CheckPostgres checks if PostgreSQL is ready
func CheckPostgres(rc *eos_io.RuntimeContext) bool {
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	_, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"exec", PostgresContainer, "pg_isready", "-U", DBUser},
		Capture: true,
	})

	return err == nil
}

// CheckLiteLLM checks if LiteLLM is ready
func CheckLiteLLM(rc *eos_io.RuntimeContext) bool {
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	_, err := execute.Run(ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-sf", LiteLLMURL + "/health/readiness"},
		Capture: true,
	})

	return err == nil
}

// VerifyConfiguration verifies database configuration
func VerifyConfiguration(rc *eos_io.RuntimeContext) (*DBVerificationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying configuration")

	result := &DBVerificationResult{
		Models:   []DBModel{},
		Prompts:  []DBPrompt{},
		Errors:   []string{},
		Warnings: []string{},
	}

	// Check models
	logger.Info("Checking models in database")
	modelsSQL := "SELECT id, model_type, name, context_size, tpm_limit, rpm_limit FROM models ORDER BY id;"

	// Execute and capture output
	ctx, cancel := context.WithTimeout(rc.Ctx, CommandTimeout)
	defer cancel()

	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"exec", PostgresContainer, "psql", "-U", DBUser, "-d", DBName, "-c", modelsSQL},
		Capture: true,
	})

	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to query models: %v", err))
	} else {
		logger.Info("Models in database", zap.String("output", output))
	}

	// Count models
	modelCount, err := querySingleValue(rc, PostgresContainer, DBUser, DBName, "SELECT COUNT(*) FROM models;")
	if err != nil {
		result.Warnings = append(result.Warnings, "Could not count models")
	} else {
		fmt.Sscanf(modelCount, "%d", &result.ModelCount)
		logger.Info("Model count", zap.Int("count", result.ModelCount))
	}

	// Check prompts
	logger.Info("Checking default assistants")
	promptsSQL := `
SELECT p.id, p.name, p.model_id, m.name as model_name, p.description
FROM prompts p
JOIN models m ON p.model_id = m.id
ORDER BY p.id
LIMIT 5;
`

	output, err = execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"exec", PostgresContainer, "psql", "-U", DBUser, "-d", DBName, "-c", promptsSQL},
		Capture: true,
	})

	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to query prompts: %v", err))
	} else {
		logger.Info("Prompts in database", zap.String("output", output))
	}

	// Verify Moni prompt exists
	moniCount, err := querySingleValue(rc, PostgresContainer, DBUser, DBName,
		"SELECT COUNT(*) FROM prompts WHERE name = 'Moni';")
	if err != nil {
		result.Warnings = append(result.Warnings, "Could not check Moni prompt")
	} else {
		var count int
		fmt.Sscanf(moniCount, "%d", &count)
		result.MoniExists = count > 0

		if result.MoniExists {
			logger.Info("'Moni' assistant is configured")
		} else {
			logger.Warn("'Moni' assistant not found in database")
			result.Warnings = append(result.Warnings, "Moni assistant not found")
		}
	}

	return result, nil
}

// VerifyRowLevelSecurity verifies RLS is properly configured
func VerifyRowLevelSecurity(rc *eos_io.RuntimeContext) (*RLSVerificationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Row Level Security (RLS)")

	result := &RLSVerificationResult{
		TablesWithRLS:    []string{},
		TablesWithoutRLS: []string{},
		PoliciesFound:    []RLSPolicy{},
		Warnings:         []string{},
		Errors:           []string{},
	}

	// Critical tables that MUST have RLS
	criticalTables := []string{"chats", "documents", "datasets", "models", "prompts", "api_keys"}

	// Step 1: Check which tables have RLS enabled
	logger.Info("Checking RLS status on tables")

	rlsCheckSQL := `
SELECT tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;
`

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"exec", PostgresContainer, "psql", "-U", DBUser, "-d", DBName, "-t", "-c", rlsCheckSQL},
		Capture: true,
	})

	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to query RLS status: %v", err))
		return result, nil
	}

	// Parse results
	rlsTables := make(map[string]bool)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if !strings.Contains(line, "|") {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}

		tablename := strings.TrimSpace(parts[0])
		rowsecurity := strings.TrimSpace(parts[1])

		if tablename == "" {
			continue
		}

		hasRLS := rowsecurity == "t" || rowsecurity == "true" || rowsecurity == "on"
		rlsTables[tablename] = hasRLS

		if hasRLS {
			result.TablesWithRLS = append(result.TablesWithRLS, tablename)
		} else {
			result.TablesWithoutRLS = append(result.TablesWithoutRLS, tablename)
		}
	}

	logger.Info("RLS table status",
		zap.Int("with_rls", len(result.TablesWithRLS)),
		zap.Int("without_rls", len(result.TablesWithoutRLS)))

	// Step 2: Check critical tables
	logger.Info("Verifying critical tables have RLS")

	criticalProtected := []string{}
	criticalUnprotected := []string{}

	for _, table := range criticalTables {
		if hasRLS, exists := rlsTables[table]; exists {
			if hasRLS {
				logger.Info("Critical table protected", zap.String("table", table))
				criticalProtected = append(criticalProtected, table)
			} else {
				logger.Error("Critical table NOT protected (SECURITY RISK!)", zap.String("table", table))
				criticalUnprotected = append(criticalUnprotected, table)
				result.Errors = append(result.Errors, fmt.Sprintf("Critical table '%s' does not have RLS enabled", table))
			}
		} else {
			logger.Warn("Critical table not found (may not exist yet)", zap.String("table", table))
			result.Warnings = append(result.Warnings, fmt.Sprintf("Critical table '%s' not found in database", table))
		}
	}

	// Step 3: Check RLS policies
	logger.Info("Checking RLS policies")

	policiesSQL := `
SELECT schemaname, tablename, policyname, cmd
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, policyname;
`

	output, err = execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"exec", PostgresContainer, "psql", "-U", DBUser, "-d", DBName, "-t", "-c", policiesSQL},
		Capture: true,
	})

	if err == nil {
		policyCount := 0
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if !strings.Contains(line, "|") || strings.TrimSpace(line) == "" {
				continue
			}

			parts := strings.Split(line, "|")
			if len(parts) >= 4 {
				policy := RLSPolicy{
					Table:      strings.TrimSpace(parts[1]),
					PolicyName: strings.TrimSpace(parts[2]),
					Command:    strings.TrimSpace(parts[3]),
				}
				result.PoliciesFound = append(result.PoliciesFound, policy)
				policyCount++
			}
		}

		if policyCount > 0 {
			logger.Info("RLS policies found", zap.Int("count", policyCount))
			result.RLSEnabled = true
		} else {
			logger.Warn("No RLS policies found")
			result.Warnings = append(result.Warnings, "No RLS policies found - multi-tenancy may rely on application-level checks only")
		}
	} else {
		logger.Warn("Could not query RLS policies")
		result.Warnings = append(result.Warnings, "Failed to query RLS policies")
	}

	// Step 4: Check team_id indexes (P1 CRITICAL - Performance)
	logger.Info("Checking team_id indexes for RLS performance")

	tablesNeedingIndexes := []string{"api_keys", "conversations", "datasets", "documents",
		"api_key_connections", "audit_trail", "document_pipelines", "integrations",
		"invitations", "oauth2_connections", "objects", "prompts", "team_users"}

	missingIndexes := []string{}

	for _, table := range tablesNeedingIndexes {
		indexSQL := fmt.Sprintf(`
			SELECT COUNT(*) FROM pg_indexes
			WHERE tablename = '%s' AND indexdef LIKE '%%team_id%%';
		`, table)

		indexCount, err := querySingleValue(rc, PostgresContainer, DBUser, DBName, indexSQL)
		if err != nil {
			logger.Debug("Could not check indexes", zap.String("table", table), zap.Error(err))
			continue
		}

		var count int
		fmt.Sscanf(indexCount, "%d", &count)

		if count == 0 {
			missingIndexes = append(missingIndexes, table)
			logger.Warn("Missing team_id index (performance issue)",
				zap.String("table", table),
				zap.String("recommendation", fmt.Sprintf("CREATE INDEX idx_%s_team_id ON %s(team_id)", table, table)),
				zap.String("impact", "Queries will do sequential scans instead of index scans"))
		} else {
			logger.Debug("Index exists", zap.String("table", table), zap.Int("count", count))
		}
	}

	if len(missingIndexes) > 0 {
		logger.Warn("RLS Performance Warning",
			zap.Int("tables_without_indexes", len(missingIndexes)),
			zap.Strings("tables", missingIndexes))
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("%d tables missing team_id indexes (will cause performance issues)", len(missingIndexes)))
	} else {
		logger.Info("All critical tables have team_id indexes")
	}

	// Step 5: Summary
	result.CriticalTablesProtected = len(criticalUnprotected) == 0 && len(criticalProtected) > 0

	if result.CriticalTablesProtected {
		logger.Info("Row Level Security: GOOD",
			zap.Int("critical_protected", len(criticalProtected)),
			zap.Int("policies_active", len(result.PoliciesFound)))
	} else if len(criticalUnprotected) > 0 {
		logger.Error("Row Level Security: CRITICAL ISSUES",
			zap.Int("unprotected_tables", len(criticalUnprotected)),
			zap.Strings("tables", criticalUnprotected))
		logger.Error("This is a SERIOUS security vulnerability! Multi-tenant data isolation is at risk")
	} else {
		logger.Warn("Row Level Security: UNKNOWN (database may not be initialized)")
	}

	return result, nil
}

// VerifyContentSecurityPolicy verifies CSP headers are properly configured
func VerifyContentSecurityPolicy(rc *eos_io.RuntimeContext) (*CSPVerificationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Content Security Policy (CSP)")

	result := &CSPVerificationResult{
		GoodDirectives:    []string{},
		WeakDirectives:    []string{},
		MissingDirectives: []string{},
		Warnings:          []string{},
		Errors:            []string{},
	}

	// Expected secure CSP directives
	recommendedDirectives := map[string]string{
		"default-src":    "'self'",
		"script-src":     "'self'",
		"style-src":      "'self' 'unsafe-inline'",
		"img-src":        "'self' data:",
		"font-src":       "'self'",
		"connect-src":    "'self'",
		"frame-ancestors": "'none'",
		"base-uri":       "'self'",
		"form-action":    "'self'",
	}

	// Dangerous patterns
	dangerousPatterns := map[string]string{
		"'unsafe-eval'":                           "Allows eval() - major XSS risk",
		"* 'unsafe-inline' 'unsafe-eval'":         "Extremely permissive - defeats CSP purpose",
		"*":                                       "Wildcard allows any source - too permissive",
	}

	// Step 1: Check if app is responding
	logger.Info("Checking for CSP headers")

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	statusCode, err := execute.Run(ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-s", "-I", AppURL, "-o", "/dev/null", "-w", "%{http_code}"},
		Capture: true,
	})

	if err != nil || statusCode != "200" {
		logger.Warn("App not responding", zap.String("url", AppURL), zap.String("status", statusCode))
		result.Warnings = append(result.Warnings, fmt.Sprintf("Could not connect to app at %s", AppURL))
		result.Errors = append(result.Errors, "App is not accessible - cannot verify CSP")
		return result, nil
	}

	// Step 2: Get headers
	output, err := execute.Run(ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-s", "-D", "-", AppURL, "-o", "/dev/null"},
		Capture: true,
	})

	if err != nil {
		logger.Warn("Could not fetch headers")
		result.Errors = append(result.Errors, "Failed to fetch HTTP headers")
		return result, nil
	}

	// Step 3: Parse headers for CSP
	var cspHeader string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "content-security-policy:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				cspHeader = strings.TrimSpace(parts[1])
				result.CSPPresent = true
				result.CSPHeader = cspHeader
				break
			}
		}
	}

	// Step 4: Analyze CSP if found
	if cspHeader != "" {
		logger.Info("Analyzing CSP configuration")

		// Check for dangerous patterns
		for pattern, risk := range dangerousPatterns {
			if strings.Contains(cspHeader, pattern) {
				logger.Error("DANGEROUS pattern found in CSP",
					zap.String("pattern", pattern),
					zap.String("risk", risk))
				result.WeakDirectives = append(result.WeakDirectives, fmt.Sprintf("%s: %s", pattern, risk))
				result.SecurityScore -= 30
			}
		}

		// Parse CSP directives
		directives := make(map[string]string)
		for _, directive := range strings.Split(cspHeader, ";") {
			directive = strings.TrimSpace(directive)
			if directive == "" {
				continue
			}

			parts := strings.SplitN(directive, " ", 2)
			if len(parts) >= 1 {
				key := parts[0]
				value := ""
				if len(parts) > 1 {
					value = parts[1]
				}
				directives[key] = value
			}
		}

		// Check for good directives
		for directive, expected := range recommendedDirectives {
			if actual, exists := directives[directive]; exists {
				if strings.Contains(actual, expected) || actual == "'self'" {
					logger.Info("Secure directive", zap.String("directive", directive))
					result.GoodDirectives = append(result.GoodDirectives, directive)
					result.SecurityScore += 10
				} else {
					logger.Warn("Suboptimal directive",
						zap.String("directive", directive),
						zap.String("actual", actual),
						zap.String("expected", expected))
					result.Warnings = append(result.Warnings, fmt.Sprintf("%s is not optimally configured", directive))
					result.SecurityScore += 5
				}
			} else {
				logger.Warn("Missing directive", zap.String("directive", directive))
				result.MissingDirectives = append(result.MissingDirectives, directive)
			}
		}

		// Summary
		if result.SecurityScore >= 70 {
			logger.Info("Content Security Policy: STRONG",
				zap.Int("score", result.SecurityScore),
				zap.Int("good_directives", len(result.GoodDirectives)),
				zap.Int("weak_directives", len(result.WeakDirectives)))
		} else if result.SecurityScore >= 40 {
			logger.Warn("Content Security Policy: MODERATE",
				zap.Int("score", result.SecurityScore))
			logger.Warn("Consider strengthening CSP configuration")
		} else {
			logger.Error("Content Security Policy: WEAK",
				zap.Int("score", result.SecurityScore))
			logger.Error("CSP provides minimal protection - vulnerable to XSS and injection attacks")
		}
	} else {
		// No CSP found
		logger.Error("NO Content Security Policy found!")
		logger.Error("Application is vulnerable to XSS, clickjacking, and data injection attacks")
		logger.Error("Recommendation: Configure CSP headers in web server")

		result.Errors = append(result.Errors, "No Content-Security-Policy header found")
		result.SecurityScore = 0
	}

	return result, nil
}

// RunFinalHealthCheck runs final health checks
func RunFinalHealthCheck(rc *eos_io.RuntimeContext) (*HealthCheckResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Phase 8: Final System Verification")

	result := &HealthCheckResult{
		ContainerHealth: make(map[string]bool),
		Errors:          []string{},
		Warnings:        []string{},
	}

	// Check PostgreSQL SSL status
	logger.Info("Verifying PostgreSQL SSL status")

	sslStatus, err := querySingleValue(rc, PostgresContainer, DBUser, DBName, "SHOW ssl;")
	if err == nil && strings.Contains(sslStatus, "on") {
		logger.Info("PostgreSQL SSL enabled")
		result.PostgresSSL = true
	} else {
		logger.Warn("Could not verify SSL status")
		result.Warnings = append(result.Warnings, "Could not verify PostgreSQL SSL")
	}

	// Check LiteLLM models endpoint
	logger.Info("Checking LiteLLM models")

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	output, err := execute.Run(ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-sf", LiteLLMURL + "/v1/models"},
		Capture: true,
	})

	if err == nil {
		modelCount := strings.Count(output, `"id"`)
		if modelCount > 0 {
			logger.Info("LiteLLM models available", zap.Int("count", modelCount))
			result.LiteLLMModels = modelCount
		} else {
			logger.Warn("Could not parse LiteLLM models response")
		}
	} else {
		logger.Warn("Could not verify LiteLLM models")
		result.Warnings = append(result.Warnings, "Could not verify LiteLLM models")
	}

	// Check web search configuration
	envVars, err := readEnvFile(MoniEnvFile)
	if err == nil {
		webSearch := envVars["ENABLE_WEB_SEARCH"]
		if strings.ToLower(webSearch) == "true" {
			logger.Warn("WARNING: Web search is ENABLED in .env")
			logger.Warn("To disable: Set ENABLE_WEB_SEARCH=false in .env")
			result.WebSearchEnabled = true
		} else {
			logger.Info("Web search is disabled")
			result.WebSearchEnabled = false
		}

		systemPrompt := envVars["MONI_SYSTEM_PROMPT"]
		if systemPrompt != "" {
			logger.Info("System prompt configured in .env")
			result.SystemPromptSet = true
		} else {
			logger.Warn("MONI_SYSTEM_PROMPT not set in .env")
			logger.Info("Note: Will fall back to prompt.txt if available")
			result.SystemPromptSet = false
		}
	}

	// Check container statuses
	logger.Info("Container statuses")

	output, err = execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"ps", "--format", "table {{.Names}}\t{{.Status}}"},
		Capture: true,
	})

	if err == nil {
		logger.Info("Container status output", zap.String("output", output))
	}

	return result, nil
}

// readEnvFile reads .env file and returns key-value pairs
func readEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	vars := make(map[string]string)
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			value = strings.Trim(value, `"'`)
			vars[key] = value
		}
	}

	return vars, nil
}
