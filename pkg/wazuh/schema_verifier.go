/* pkg/wazuh/schema_verifier.go */

package wazuh

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SchemaObject represents a database object that needs verification
type SchemaObject struct {
	Name         string
	Type         string
	Status       string
	Details      string
	ActionNeeded string
}

// SchemaVerificationResult holds the complete verification results
type SchemaVerificationResult struct {
	EnumTypes     []SchemaObject
	Tables        []SchemaObject
	Indexes       []SchemaObject
	Views         []SchemaObject
	Functions     []SchemaObject
	Triggers      []SchemaObject
	OverallStatus string
	MissingCount  int
	Timestamp     time.Time
}

// SchemaVerifier handles database schema verification
type SchemaVerifier struct {
	db *sql.DB
}

// NewSchemaVerifier creates a new schema verifier instance
func NewSchemaVerifier(db *sql.DB) *SchemaVerifier {
	return &SchemaVerifier{
		db: db,
	}
}

// VerifyCompleteSchema performs comprehensive schema verification
func (sv *SchemaVerifier) VerifyCompleteSchema(rc *eos_io.RuntimeContext) (*SchemaVerificationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Starting comprehensive schema verification")

	result := &SchemaVerificationResult{
		Timestamp: time.Now(),
	}

	// Verify each component type
	var err error

	result.EnumTypes, err = sv.verifyEnumTypes(rc)
	if err != nil {
		logger.Error("Failed to verify enum types", zap.Error(err))
		return nil, fmt.Errorf("enum verification failed: %w", err)
	}

	result.Tables, err = sv.verifyTables(rc)
	if err != nil {
		logger.Error("Failed to verify tables", zap.Error(err))
		return nil, fmt.Errorf("table verification failed: %w", err)
	}

	result.Indexes, err = sv.verifyIndexes(rc)
	if err != nil {
		logger.Error("Failed to verify indexes", zap.Error(err))
		return nil, fmt.Errorf("index verification failed: %w", err)
	}

	result.Views, err = sv.verifyViews(rc)
	if err != nil {
		logger.Error("Failed to verify views", zap.Error(err))
		return nil, fmt.Errorf("view verification failed: %w", err)
	}

	result.Functions, err = sv.verifyFunctions(rc)
	if err != nil {
		logger.Error("Failed to verify functions", zap.Error(err))
		return nil, fmt.Errorf("function verification failed: %w", err)
	}

	result.Triggers, err = sv.verifyTriggers(rc)
	if err != nil {
		logger.Error("Failed to verify triggers", zap.Error(err))
		return nil, fmt.Errorf("trigger verification failed: %w", err)
	}

	// Calculate overall status
	result.calculateOverallStatus()

	logger.Info(" Schema verification completed",
		zap.String("status", result.OverallStatus),
		zap.Int("missing_objects", result.MissingCount))

	return result, nil
}

// verifyEnumTypes checks for required enum types
func (sv *SchemaVerifier) verifyEnumTypes(rc *eos_io.RuntimeContext) ([]SchemaObject, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying enum types")

	expectedEnums := []string{"alert_state", "parser_type"}
	var results []SchemaObject

	query := `
		SELECT typname 
		FROM pg_type 
		WHERE typname = ANY($1)
	`

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	rows, err := sv.db.QueryContext(ctx, query, expectedEnums)
	if err != nil {
		return nil, fmt.Errorf("failed to query enum types: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			logger.Warn("Failed to close rows", zap.Error(closeErr))
		}
	}()

	// Build map of existing enums
	existingEnums := make(map[string]bool)
	for rows.Next() {
		var enumName string
		if err := rows.Scan(&enumName); err != nil {
			return nil, fmt.Errorf("failed to scan enum name: %w", err)
		}
		existingEnums[enumName] = true
	}

	// Check each expected enum
	for _, enumName := range expectedEnums {
		obj := SchemaObject{
			Name: enumName,
			Type: "ENUM",
		}

		if existingEnums[enumName] {
			obj.Status = "✓ EXISTS"
			obj.Details = "Enum type is properly defined"
		} else {
			obj.Status = "✗ MISSING"
			obj.ActionNeeded = fmt.Sprintf("CREATE TYPE %s AS ENUM (...)", enumName)

			// Provide specific creation commands
			switch enumName {
			case "alert_state":
				obj.ActionNeeded = `CREATE TYPE alert_state AS ENUM (
    'new', 'enriched', 'analyzed', 'structured', 
    'formatted', 'sent', 'failed', 'archived'
);`
			case "parser_type":
				obj.ActionNeeded = `CREATE TYPE parser_type AS ENUM (
    'security_analysis', 'executive_summary', 'investigation_guide',
    'wazuh_notify_short', 'hybrid', 'custom'
);`
			}
		}

		results = append(results, obj)
	}

	return results, nil
}

// verifyTables checks for required tables and their structure
func (sv *SchemaVerifier) verifyTables(rc *eos_io.RuntimeContext) ([]SchemaObject, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying tables")

	expectedTables := []string{"agents", "alerts", "parser_metrics"}
	var results []SchemaObject

	query := `
		SELECT table_name, 
		       (SELECT COUNT(*) FROM information_schema.columns 
		        WHERE table_schema = 'public' AND table_name = t.table_name) as column_count
		FROM information_schema.tables t
		WHERE table_schema = 'public' 
		  AND table_name = ANY($1)
	`

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	rows, err := sv.db.QueryContext(ctx, query, expectedTables)
	if err != nil {
		return nil, fmt.Errorf("failed to query tables: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			logger.Warn("Failed to close rows", zap.Error(closeErr))
		}
	}()

	// Build map of existing tables
	existingTables := make(map[string]int)
	for rows.Next() {
		var tableName string
		var columnCount int
		if err := rows.Scan(&tableName, &columnCount); err != nil {
			return nil, fmt.Errorf("failed to scan table info: %w", err)
		}
		existingTables[tableName] = columnCount
	}

	// Check each expected table
	for _, tableName := range expectedTables {
		obj := SchemaObject{
			Name: tableName,
			Type: "TABLE",
		}

		if columnCount, exists := existingTables[tableName]; exists {
			obj.Status = "✓ EXISTS"
			obj.Details = fmt.Sprintf("%d columns", columnCount)

			// Verify critical columns for alerts table
			if tableName == "alerts" {
				if err := sv.verifyAlertsTableColumns(rc, &obj); err != nil {
					logger.Warn("Failed to verify alerts table columns", zap.Error(err))
				}
			}
		} else {
			obj.Status = "✗ MISSING"
			obj.ActionNeeded = fmt.Sprintf("Create table using schema.sql definition for %s", tableName)
		}

		results = append(results, obj)
	}

	return results, nil
}

// verifyAlertsTableColumns checks critical columns in alerts table
func (sv *SchemaVerifier) verifyAlertsTableColumns(rc *eos_io.RuntimeContext, obj *SchemaObject) error {
	logger := otelzap.Ctx(rc.Ctx)
	criticalColumns := []string{
		"state", "ingest_timestamp", "parser_used", "parser_success",
		"prompt_type", "structured_at", "email_error", "archived_at",
	}

	query := `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'alerts'
		  AND column_name = ANY($1)
	`

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	rows, err := sv.db.QueryContext(ctx, query, criticalColumns)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			logger.Warn("Failed to close rows", zap.Error(closeErr))
		}
	}()

	foundColumns := make(map[string]bool)
	for rows.Next() {
		var colName string
		if err := rows.Scan(&colName); err != nil {
			continue
		}
		foundColumns[colName] = true
	}

	missingColumns := []string{}
	for _, col := range criticalColumns {
		if !foundColumns[col] {
			missingColumns = append(missingColumns, col)
		}
	}

	if len(missingColumns) > 0 {
		obj.Details += fmt.Sprintf(" (Missing columns: %s)", strings.Join(missingColumns, ", "))
		obj.Status = "⚠ INCOMPLETE"
		obj.ActionNeeded = "Some critical columns are missing - check schema.sql"
	}

	return nil
}

// verifyIndexes checks for performance-critical indexes
func (sv *SchemaVerifier) verifyIndexes(rc *eos_io.RuntimeContext) ([]SchemaObject, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying indexes")

	expectedIndexes := map[string]string{
		"idx_agents_status":              "agents",
		"idx_agents_last_seen":           "agents",
		"idx_agents_groups":              "agents",
		"idx_alerts_state_timestamp":     "alerts",
		"idx_alerts_agent_rule":          "alerts",
		"idx_alerts_prompt_type":         "alerts",
		"idx_alerts_parser_performance":  "alerts",
		"idx_parser_metrics_performance": "parser_metrics",
	}

	var results []SchemaObject

	query := `
		SELECT indexname, tablename
		FROM pg_indexes
		WHERE schemaname = 'public'
		  AND indexname = ANY($1)
	`

	indexNames := make([]string, 0, len(expectedIndexes))
	for name := range expectedIndexes {
		indexNames = append(indexNames, name)
	}

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	rows, err := sv.db.QueryContext(ctx, query, indexNames)
	if err != nil {
		return nil, fmt.Errorf("failed to query indexes: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			logger.Warn("Failed to close rows", zap.Error(closeErr))
		}
	}()

	// Build map of existing indexes
	existingIndexes := make(map[string]bool)
	for rows.Next() {
		var indexName, tableName string
		if err := rows.Scan(&indexName, &tableName); err != nil {
			return nil, fmt.Errorf("failed to scan index info: %w", err)
		}
		existingIndexes[indexName] = true
	}

	// Check each expected index
	for indexName, tableName := range expectedIndexes {
		obj := SchemaObject{
			Name:    indexName,
			Type:    "INDEX",
			Details: fmt.Sprintf("on table %s", tableName),
		}

		if existingIndexes[indexName] {
			obj.Status = "✓ EXISTS"
		} else {
			obj.Status = "✗ MISSING"
			obj.ActionNeeded = fmt.Sprintf("Performance may be degraded - create index %s", indexName)
		}

		results = append(results, obj)
	}

	return results, nil
}

// verifyViews checks for monitoring views
func (sv *SchemaVerifier) verifyViews(rc *eos_io.RuntimeContext) ([]SchemaObject, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying views")

	expectedViews := []string{
		"pipeline_health", "pipeline_bottlenecks", "parser_performance",
		"parser_error_analysis", "recent_failures", "failure_summary",
	}

	var results []SchemaObject

	query := `
		SELECT viewname
		FROM pg_views
		WHERE schemaname = 'public'
		  AND viewname = ANY($1)
	`

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	rows, err := sv.db.QueryContext(ctx, query, expectedViews)
	if err != nil {
		return nil, fmt.Errorf("failed to query views: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			logger.Warn("Failed to close rows", zap.Error(closeErr))
		}
	}()

	// Build map of existing views
	existingViews := make(map[string]bool)
	for rows.Next() {
		var viewName string
		if err := rows.Scan(&viewName); err != nil {
			return nil, fmt.Errorf("failed to scan view name: %w", err)
		}
		existingViews[viewName] = true
	}

	// Check each expected view
	for _, viewName := range expectedViews {
		obj := SchemaObject{
			Name: viewName,
			Type: "VIEW",
		}

		if existingViews[viewName] {
			obj.Status = "✓ EXISTS"

			// Test if view is functional
			if err := sv.testViewFunctionality(rc, viewName); err != nil {
				obj.Status = "⚠ EXISTS BUT BROKEN"
				obj.Details = fmt.Sprintf("Error: %v", err)
				obj.ActionNeeded = "View exists but may need to be recreated"
			} else {
				obj.Details = "View is functional"
			}
		} else {
			obj.Status = "✗ MISSING"
			obj.ActionNeeded = fmt.Sprintf("Dashboard feature '%s' will not work", viewName)
		}

		results = append(results, obj)
	}

	return results, nil
}

// testViewFunctionality tests if a view can be queried
func (sv *SchemaVerifier) testViewFunctionality(rc *eos_io.RuntimeContext, viewName string) error {
	query := fmt.Sprintf("SELECT 1 FROM %s LIMIT 1", viewName)

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	_, err := sv.db.ExecContext(ctx, query)
	return err
}

// verifyFunctions checks for required functions
func (sv *SchemaVerifier) verifyFunctions(rc *eos_io.RuntimeContext) ([]SchemaObject, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying functions")

	expectedFunctions := []string{
		"notify_state_change", "notify_new_alert",
		"archive_old_alerts", "get_pipeline_stats",
	}

	var results []SchemaObject

	query := `
		SELECT proname, pg_get_function_arguments(p.oid) as arguments
		FROM pg_proc p
		JOIN pg_namespace n ON p.pronamespace = n.oid
		WHERE n.nspname = 'public'
		  AND proname = ANY($1)
	`

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	rows, err := sv.db.QueryContext(ctx, query, expectedFunctions)
	if err != nil {
		return nil, fmt.Errorf("failed to query functions: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			logger.Warn("Failed to close rows", zap.Error(closeErr))
		}
	}()

	// Build map of existing functions
	existingFunctions := make(map[string]string)
	for rows.Next() {
		var funcName, arguments string
		if err := rows.Scan(&funcName, &arguments); err != nil {
			return nil, fmt.Errorf("failed to scan function info: %w", err)
		}
		existingFunctions[funcName] = arguments
	}

	// Check each expected function
	for _, funcName := range expectedFunctions {
		obj := SchemaObject{
			Name: funcName,
			Type: "FUNCTION",
		}

		if args, exists := existingFunctions[funcName]; exists {
			obj.Status = "✓ EXISTS"
			obj.Details = fmt.Sprintf("Arguments: %s", args)
		} else {
			obj.Status = "✗ MISSING"

			switch funcName {
			case "notify_state_change", "notify_new_alert":
				obj.ActionNeeded = "Pipeline notifications will not work"
			case "archive_old_alerts":
				obj.ActionNeeded = "Cannot archive old alerts automatically"
			case "get_pipeline_stats":
				obj.ActionNeeded = "Pipeline statistics unavailable"
			}
		}

		results = append(results, obj)
	}

	return results, nil
}

// verifyTriggers checks for required triggers
func (sv *SchemaVerifier) verifyTriggers(rc *eos_io.RuntimeContext) ([]SchemaObject, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying triggers")

	expectedTriggers := []string{"trg_alert_state_change", "trg_alert_new"}
	var results []SchemaObject

	// First check if alerts table exists
	var alertsExists bool
	err := sv.db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables 
			WHERE table_schema = 'public' AND table_name = 'alerts'
		)
	`).Scan(&alertsExists)

	if err != nil || !alertsExists {
		for _, triggerName := range expectedTriggers {
			results = append(results, SchemaObject{
				Name:         triggerName,
				Type:         "TRIGGER",
				Status:       "✗ CANNOT VERIFY",
				Details:      "Alerts table does not exist",
				ActionNeeded: "Create alerts table first",
			})
		}
		return results, nil
	}

	query := `
		SELECT tgname
		FROM pg_trigger
		WHERE tgrelid = 'alerts'::regclass
		  AND tgname = ANY($1)
	`

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	rows, err := sv.db.QueryContext(ctx, query, expectedTriggers)
	if err != nil {
		return nil, fmt.Errorf("failed to query triggers: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			logger.Warn("Failed to close rows", zap.Error(closeErr))
		}
	}()

	// Build map of existing triggers
	existingTriggers := make(map[string]bool)
	for rows.Next() {
		var triggerName string
		if err := rows.Scan(&triggerName); err != nil {
			return nil, fmt.Errorf("failed to scan trigger name: %w", err)
		}
		existingTriggers[triggerName] = true
	}

	// Check each expected trigger
	for _, triggerName := range expectedTriggers {
		obj := SchemaObject{
			Name:    triggerName,
			Type:    "TRIGGER",
			Details: "on alerts table",
		}

		if existingTriggers[triggerName] {
			obj.Status = "✓ EXISTS"
		} else {
			obj.Status = "✗ MISSING"

			switch triggerName {
			case "trg_alert_state_change":
				obj.ActionNeeded = "State change notifications will not fire"
			case "trg_alert_new":
				obj.ActionNeeded = "New alert notifications will not fire"
			}
		}

		results = append(results, obj)
	}

	return results, nil
}

// calculateOverallStatus determines the overall health of the schema
func (result *SchemaVerificationResult) calculateOverallStatus() {
	missingCount := 0
	warningCount := 0

	// Count issues across all object types
	allObjects := [][]SchemaObject{
		result.EnumTypes, result.Tables, result.Indexes,
		result.Views, result.Functions, result.Triggers,
	}

	for _, objects := range allObjects {
		for _, obj := range objects {
			if strings.Contains(obj.Status, "MISSING") {
				missingCount++
			} else if strings.Contains(obj.Status, "⚠") {
				warningCount++
			}
		}
	}

	result.MissingCount = missingCount

	if missingCount == 0 && warningCount == 0 {
		result.OverallStatus = " Database fully matches schema.sql!"
	} else if missingCount == 0 {
		result.OverallStatus = fmt.Sprintf("  Database has %d warnings but no missing objects", warningCount)
	} else {
		result.OverallStatus = fmt.Sprintf(" Database requires updates: %d missing objects, %d warnings", missingCount, warningCount)
	}
}

// GenerateReport creates a formatted report of the verification results
func (result *SchemaVerificationResult) GenerateReport() string {
	var report strings.Builder

	report.WriteString("\n═══════════════════════════════════════════════════════════════\n")
	report.WriteString("       WAZUH PIPELINE SCHEMA VERIFICATION REPORT\n")
	report.WriteString("═══════════════════════════════════════════════════════════════\n\n")
	report.WriteString(fmt.Sprintf("Timestamp: %s\n", result.Timestamp.Format("2006-01-02 15:04:05")))
	report.WriteString(fmt.Sprintf("Overall Status: %s\n\n", result.OverallStatus))

	// Report each category
	categories := []struct {
		name    string
		objects []SchemaObject
	}{
		{"ENUM TYPES", result.EnumTypes},
		{"TABLES", result.Tables},
		{"INDEXES", result.Indexes},
		{"VIEWS", result.Views},
		{"FUNCTIONS", result.Functions},
		{"TRIGGERS", result.Triggers},
	}

	for _, cat := range categories {
		report.WriteString(fmt.Sprintf("\n── %s ──────────────────────────────\n", cat.name))

		for _, obj := range cat.objects {
			report.WriteString(fmt.Sprintf("\n  %s: %s\n", obj.Name, obj.Status))

			if obj.Details != "" {
				report.WriteString(fmt.Sprintf("    Details: %s\n", obj.Details))
			}

			if obj.ActionNeeded != "" {
				report.WriteString(fmt.Sprintf("    Action: %s\n", obj.ActionNeeded))
			}
		}
	}

	// Add migration instructions if needed
	if result.MissingCount > 0 {
		report.WriteString("\n\n═══════════════════════════════════════════════════════════════\n")
		report.WriteString("                    MIGRATION REQUIRED\n")
		report.WriteString("═══════════════════════════════════════════════════════════════\n\n")
		report.WriteString("To fix missing objects, run the SQL statements from schema.sql\n")
		report.WriteString("in the order they appear. Pay special attention to:\n")
		report.WriteString("1. Create ENUM types first (alert_state, parser_type)\n")
		report.WriteString("2. Create tables in order (agents, alerts, parser_metrics)\n")
		report.WriteString("3. Create indexes after tables\n")
		report.WriteString("4. Create functions before triggers\n")
		report.WriteString("5. Create views last (they depend on tables)\n")
	}

	return report.String()
}
