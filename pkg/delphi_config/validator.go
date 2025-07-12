package delphi_config

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// ConfigValidator handles Delphi configuration validation
type ConfigValidator struct {
	config  *DelphiConfig
	results []ValidationResult
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator(config *DelphiConfig) *ConfigValidator {
	return &ConfigValidator{
		config:  config,
		results: make([]ValidationResult, 0),
	}
}

// ValidateAll performs all validation checks
func (v *ConfigValidator) ValidateAll() *ValidationSummary {
	v.results = make([]ValidationResult, 0)

	// Run all validations
	v.validateDatabase()
	v.validateNotificationChannels()
	v.validateRequiredEnvVars()
	v.validateLLMConfig()
	v.validateSMTPConfig()
	v.validateFilePaths()
	v.validateParserConfig()
	v.validateSecurityConfig()
	v.validateWazuhConfig()

	// Categorize results
	summary := &ValidationSummary{
		Timestamp: time.Now(),
		Errors:    make([]ValidationResult, 0),
		Warnings:  make([]ValidationResult, 0),
		Info:      make([]ValidationResult, 0),
	}

	for _, result := range v.results {
		switch result.Level {
		case "error":
			summary.Errors = append(summary.Errors, result)
		case "warning":
			summary.Warnings = append(summary.Warnings, result)
		case "info":
			summary.Info = append(summary.Info, result)
		}
	}

	summary.Success = len(summary.Errors) == 0
	return summary
}

// validateDatabase checks database connectivity and schema
func (v *ConfigValidator) validateDatabase() {
	if v.config.Database.DSN == "" {
		v.addError("database", "PG_DSN environment variable not set")
		return
	}

	db, err := sql.Open("postgres", v.config.Database.DSN)
	if err != nil {
		v.addError("database", fmt.Sprintf("Database connection failed: %v", err))
		return
	}
	defer func() {
		if err := db.Close(); err != nil {
			v.addError("database", fmt.Sprintf("Failed to close database connection: %v", err))
		}
	}()

	if err := db.Ping(); err != nil {
		v.addError("database", fmt.Sprintf("Database ping failed: %v", err))
		return
	}

	v.addInfo("database", "Database connectivity successful")

	// Validate required tables
	for _, table := range v.config.Database.RequiredTables {
		if !v.tableExists(db, table) {
			v.addError("database", fmt.Sprintf("Required table '%s' does not exist", table))
		} else {
			v.addInfo("database", fmt.Sprintf("Table '%s' exists", table))
		}
	}

	// Validate required columns
	for table, columns := range v.config.Database.RequiredColumns {
		existing := v.getTableColumns(db, table)
		for _, col := range columns {
			if !contains(existing, col) {
				v.addError("database", fmt.Sprintf("Required column '%s' missing from table '%s'", col, table))
			}
		}
		if len(columns) > 0 && len(v.getErrors()) == 0 {
			v.addInfo("database", fmt.Sprintf("All required columns present in table '%s'", table))
		}
	}

	// Validate required enums
	for enumType, values := range v.config.Database.RequiredEnums {
		existing := v.getEnumValues(db, enumType)
		missing := findMissing(values, existing)
		if len(missing) > 0 {
			v.addError("database", fmt.Sprintf("Missing enum values in '%s': %v", enumType, missing))
		} else {
			v.addInfo("database", fmt.Sprintf("All required enum values present in '%s'", enumType))
		}
	}

	// Validate notification functions
	for _, function := range v.config.Database.RequiredFunctions {
		if !v.functionExists(db, function) {
			v.addWarning("database", fmt.Sprintf("Notification function '%s' does not exist", function))
		}
	}

	// Check optional tables
	for _, table := range v.config.Database.OptionalTables {
		if !v.tableExists(db, table) {
			v.addWarning("database", fmt.Sprintf("Optional table '%s' does not exist", table))
		} else {
			v.addInfo("database", fmt.Sprintf("Optional table '%s' exists", table))
		}
	}
}

// validateNotificationChannels checks PostgreSQL notification setup
func (v *ConfigValidator) validateNotificationChannels() {
	if v.config.Database.DSN == "" {
		return // Skip if no database connection
	}

	db, err := sql.Open("postgres", v.config.Database.DSN)
	if err != nil {
		return // Skip if database connection fails
	}
	defer func() {
		if err := db.Close(); err != nil {
			v.addWarning("database", fmt.Sprintf("Failed to close database connection: %v", err))
		}
	}()

	// Check notification functions
	functions := v.getNotificationFunctions(db)
	for _, reqFunc := range v.config.NotificationChannels.RequiredFunctions {
		if !contains(functions, reqFunc) {
			v.addWarning("notifications", fmt.Sprintf("Missing notification function: %s", reqFunc))
		}
	}

	if len(functions) > 0 {
		v.addInfo("notifications", fmt.Sprintf("Found %d notification functions", len(functions)))
	}

	// Check triggers on alerts table
	triggers := v.getTableTriggers(db, "alerts")
	if len(triggers) == 0 {
		v.addWarning("notifications", "No triggers found on alerts table")
	} else {
		v.addInfo("notifications", fmt.Sprintf("Found %d triggers on alerts table", len(triggers)))
	}
}

// validateRequiredEnvVars checks critical environment variables
func (v *ConfigValidator) validateRequiredEnvVars() {
	// Critical variables
	critical := map[string]string{
		"PG_DSN": "Database connection string",
	}

	for envVar, desc := range critical {
		if os.Getenv(envVar) == "" {
			v.addError("environment", fmt.Sprintf("Missing critical variable %s: %s", envVar, desc))
		} else {
			v.addInfo("environment", fmt.Sprintf("✓ %s is set", envVar))
		}
	}

	// LLM configuration (at least one provider required)
	hasOpenAI := os.Getenv("OPENAI_API_KEY") != ""
	hasAzure := os.Getenv("AZURE_OPENAI_API_KEY") != "" &&
		os.Getenv("ENDPOINT_URL") != "" &&
		os.Getenv("DEPLOYMENT_NAME") != ""

	if !hasOpenAI && !hasAzure {
		v.addError("environment", "Missing LLM configuration: Need either OpenAI or Azure OpenAI credentials")
	} else if hasOpenAI {
		v.addInfo("environment", "✓ OpenAI configuration detected")
	} else if hasAzure {
		v.addInfo("environment", "✓ Azure OpenAI configuration detected")
	}
}

// validateLLMConfig checks LLM provider configuration
func (v *ConfigValidator) validateLLMConfig() {
	// Check prompt file
	if v.config.FilePaths.PromptFile != "" {
		if _, err := os.Stat(v.config.FilePaths.PromptFile); os.IsNotExist(err) {
			v.addWarning("llm", fmt.Sprintf("Prompt file not found: %s", v.config.FilePaths.PromptFile))
		} else {
			v.addInfo("llm", fmt.Sprintf("✓ Prompt file exists: %s", v.config.FilePaths.PromptFile))
		}
	}

	// Check prompt directory
	if v.config.FilePaths.PromptDirectory != "" {
		if stat, err := os.Stat(v.config.FilePaths.PromptDirectory); os.IsNotExist(err) || !stat.IsDir() {
			v.addWarning("llm", fmt.Sprintf("Prompt directory not found: %s", v.config.FilePaths.PromptDirectory))
		} else {
			files, _ := filepath.Glob(filepath.Join(v.config.FilePaths.PromptDirectory, "*.txt"))
			v.addInfo("llm", fmt.Sprintf("✓ Found %d prompt files in %s", len(files), v.config.FilePaths.PromptDirectory))
		}
	}

	// Validate LLM configuration
	if v.config.LLM.MaxTokens < 100 || v.config.LLM.MaxTokens > 8000 {
		v.addWarning("llm", fmt.Sprintf("MaxTokens should be 100-8000, got %d", v.config.LLM.MaxTokens))
	}

	if v.config.LLM.Temperature < 0.0 || v.config.LLM.Temperature > 2.0 {
		v.addWarning("llm", fmt.Sprintf("Temperature should be 0.0-2.0, got %.2f", v.config.LLM.Temperature))
	}
}

// validateSMTPConfig checks email configuration
func (v *ConfigValidator) validateSMTPConfig() {
	smtpVars := []string{"SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_FROM"}
	missing := make([]string, 0)

	for _, envVar := range smtpVars {
		if os.Getenv(envVar) == "" {
			missing = append(missing, envVar)
		}
	}

	if len(missing) > 0 {
		v.addWarning("smtp", fmt.Sprintf("Missing SMTP variables: %v", missing))
	} else {
		v.addInfo("smtp", "✓ SMTP configuration complete")
	}

	// Validate port range
	if v.config.SMTP.Port < 1 || v.config.SMTP.Port > 65535 {
		v.addWarning("smtp", fmt.Sprintf("SMTP port should be 1-65535, got %d", v.config.SMTP.Port))
	}
}

// validateFilePaths checks file and directory paths
func (v *ConfigValidator) validateFilePaths() {
	paths := map[string]string{
		"Log directory":    v.config.FilePaths.LogDirectory,
		"Email template":   v.config.FilePaths.EmailTemplatePath,
		"Data directory":   v.config.FilePaths.DataDirectory,
		"Backup directory": v.config.FilePaths.BackupDirectory,
	}

	for desc, path := range paths {
		if path == "" {
			continue // Skip empty optional paths
		}

		if _, err := os.Stat(path); os.IsNotExist(err) {
			if strings.Contains(desc, "directory") {
				v.addWarning("files", fmt.Sprintf("%s does not exist: %s", desc, path))
			} else {
				v.addWarning("files", fmt.Sprintf("%s not found: %s", desc, path))
			}
		} else {
			v.addInfo("files", fmt.Sprintf("✓ %s exists: %s", desc, path))
		}
	}
}

// validateParserConfig checks parser configuration values
func (v *ConfigValidator) validateParserConfig() {
	// Validate circuit breaker settings
	if v.config.Parser.FailureThreshold < 1 || v.config.Parser.FailureThreshold > 20 {
		v.addWarning("parser", fmt.Sprintf("FailureThreshold should be 1-20, got %d", v.config.Parser.FailureThreshold))
	}

	if v.config.Parser.FailureTimeout < time.Minute || v.config.Parser.FailureTimeout > time.Hour {
		v.addWarning("parser", fmt.Sprintf("FailureTimeout should be 1m-1h, got %v", v.config.Parser.FailureTimeout))
	}

	// Validate A/B testing percentage
	if v.config.Parser.ABTestPercentage < 0 || v.config.Parser.ABTestPercentage > 100 {
		v.addWarning("parser", fmt.Sprintf("ABTestPercentage should be 0-100, got %d", v.config.Parser.ABTestPercentage))
	}

	// Check environment variable overrides
	if threshold := os.Getenv("PARSER_FAILURE_THRESHOLD"); threshold != "" {
		if val, err := strconv.Atoi(threshold); err != nil || val < 1 || val > 20 {
			v.addError("parser", "Invalid PARSER_FAILURE_THRESHOLD: must be integer 1-20")
		}
	}

	v.addInfo("parser", fmt.Sprintf("✓ Circuit breaker: %d failures, %v timeout",
		v.config.Parser.FailureThreshold, v.config.Parser.FailureTimeout))
	v.addInfo("parser", fmt.Sprintf("✓ A/B testing: %d%%", v.config.Parser.ABTestPercentage))
}

// validateSecurityConfig checks security settings
func (v *ConfigValidator) validateSecurityConfig() {
	authToken := os.Getenv("WEBHOOK_AUTH_TOKEN")
	if authToken == "" {
		v.addWarning("security", "WEBHOOK_AUTH_TOKEN not set - webhook will be unprotected")
	} else if len(authToken) < 16 {
		v.addWarning("security", "WEBHOOK_AUTH_TOKEN should be at least 16 characters")
	} else {
		v.addInfo("security", "✓ Webhook authentication configured")
	}

	// Validate rate limiting
	if v.config.Security.RateLimitEnabled && v.config.Security.RateLimitPerMinute < 1 {
		v.addWarning("security", "Rate limit per minute should be at least 1")
	}
}

// validateWazuhConfig checks Wazuh API configuration
func (v *ConfigValidator) validateWazuhConfig() {
	wazuhVars := []string{"WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASSWD"}
	missing := make([]string, 0)

	for _, envVar := range wazuhVars {
		if os.Getenv(envVar) == "" {
			missing = append(missing, envVar)
		}
	}

	if len(missing) > 0 {
		v.addWarning("wazuh", fmt.Sprintf("Missing Wazuh API variables: %v", missing))
	} else {
		v.addInfo("wazuh", "✓ Wazuh API configuration complete")
	}
}

// Helper methods for database queries
func (v *ConfigValidator) tableExists(db *sql.DB, tableName string) bool {
	var exists bool
	query := `SELECT EXISTS (
		SELECT 1 FROM information_schema.tables 
		WHERE table_name = $1
	)`
	db.QueryRow(query, tableName).Scan(&exists)
	return exists
}

func (v *ConfigValidator) getTableColumns(db *sql.DB, tableName string) []string {
	columns := make([]string, 0)
	query := `SELECT column_name FROM information_schema.columns WHERE table_name = $1`
	rows, err := db.Query(query, tableName)
	if err != nil {
		return columns
	}
	defer func() {
		if err := rows.Close(); err != nil {
			v.addWarning("database", fmt.Sprintf("Failed to close database rows: %v", err))
		}
	}()

	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err == nil {
			columns = append(columns, column)
		}
	}
	return columns
}

func (v *ConfigValidator) getEnumValues(db *sql.DB, enumType string) []string {
	values := make([]string, 0)
	query := `SELECT enumlabel FROM pg_enum WHERE enumtypid = $1::regtype ORDER BY enumsortorder`
	rows, err := db.Query(query, enumType)
	if err != nil {
		return values
	}
	defer func() {
		if err := rows.Close(); err != nil {
			v.addWarning("database", fmt.Sprintf("Failed to close database rows: %v", err))
		}
	}()

	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err == nil {
			values = append(values, value)
		}
	}
	return values
}

func (v *ConfigValidator) functionExists(db *sql.DB, functionName string) bool {
	var exists bool
	query := `SELECT EXISTS (
		SELECT 1 FROM information_schema.routines 
		WHERE routine_name = $1 AND routine_type = 'FUNCTION'
	)`
	db.QueryRow(query, functionName).Scan(&exists)
	return exists
}

func (v *ConfigValidator) getNotificationFunctions(db *sql.DB) []string {
	functions := make([]string, 0)
	query := `SELECT routine_name FROM information_schema.routines 
		WHERE routine_type = 'FUNCTION' AND routine_name LIKE '%notify%'`
	rows, err := db.Query(query)
	if err != nil {
		return functions
	}
	defer func() {
		if err := rows.Close(); err != nil {
			v.addWarning("database", fmt.Sprintf("Failed to close database rows: %v", err))
		}
	}()

	for rows.Next() {
		var function string
		if err := rows.Scan(&function); err == nil {
			functions = append(functions, function)
		}
	}
	return functions
}

func (v *ConfigValidator) getTableTriggers(db *sql.DB, tableName string) []string {
	triggers := make([]string, 0)
	query := `SELECT trigger_name FROM information_schema.triggers WHERE event_object_table = $1`
	rows, err := db.Query(query, tableName)
	if err != nil {
		return triggers
	}
	defer func() {
		if err := rows.Close(); err != nil {
			v.addWarning("database", fmt.Sprintf("Failed to close database rows: %v", err))
		}
	}()

	for rows.Next() {
		var trigger string
		if err := rows.Scan(&trigger); err == nil {
			triggers = append(triggers, trigger)
		}
	}
	return triggers
}

// Helper methods for validation results
func (v *ConfigValidator) addError(source, message string) {
	v.results = append(v.results, ValidationResult{
		Level:   "error",
		Source:  source,
		Message: message,
	})
}

func (v *ConfigValidator) addWarning(source, message string) {
	v.results = append(v.results, ValidationResult{
		Level:   "warning",
		Source:  source,
		Message: message,
	})
}

func (v *ConfigValidator) addInfo(source, message string) {
	v.results = append(v.results, ValidationResult{
		Level:   "info",
		Source:  source,
		Message: message,
	})
}

func (v *ConfigValidator) getErrors() []ValidationResult {
	errors := make([]ValidationResult, 0)
	for _, result := range v.results {
		if result.Level == "error" {
			errors = append(errors, result)
		}
	}
	return errors
}

// Utility functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func findMissing(required, existing []string) []string {
	missing := make([]string, 0)
	for _, req := range required {
		if !contains(existing, req) {
			missing = append(missing, req)
		}
	}
	return missing
}
