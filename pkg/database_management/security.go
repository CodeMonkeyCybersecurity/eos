// pkg/database_management/security.go
package database_management

import (
	"fmt"
	"strings"
)

// validateSQLQuerySafety performs comprehensive SQL injection prevention validation
// This function implements a multi-layer defense against SQL injection attacks
func validateSQLQuerySafety(query string) error {
	if query == "" {
		return fmt.Errorf("empty query not allowed")
	}

	// Convert to uppercase for pattern matching (case-insensitive detection)
	upperQuery := strings.ToUpper(strings.TrimSpace(query))

	// Block dangerous SQL keywords that could be used for data destruction or privilege escalation
	dangerousKeywords := []string{
		"DROP TABLE", "DROP DATABASE", "DROP SCHEMA", "DROP VIEW", "DROP INDEX",
		"TRUNCATE", "DELETE FROM", // Data destruction
		"ALTER TABLE", "ALTER DATABASE", "ALTER SCHEMA", // Schema modification
		"CREATE USER", "DROP USER", "ALTER USER", // User management
		"GRANT", "REVOKE", // Privilege management
		"INSERT INTO", "UPDATE SET", // Data modification (could be allowed with additional validation)
		"EXEC", "EXECUTE", "SP_", "XP_", // Stored procedure execution
		"SHUTDOWN", "KILL", // System commands
		"BACKUP", "RESTORE", // Backup operations
		"WAITFOR", "DELAY", // Time-based attacks
		"BULK INSERT", "OPENROWSET", "OPENDATASOURCE", // Bulk operations
		"INTO OUTFILE", "INTO DUMPFILE", "LOAD_FILE", // File operations
		"--", "/*", "*/", // Comment injection
	}

	for _, keyword := range dangerousKeywords {
		if strings.Contains(upperQuery, keyword) {
			return fmt.Errorf("dangerous SQL keyword detected: %s", strings.ToLower(keyword))
		}
	}

	// Block SQL injection patterns
	injectionPatterns := []string{
		// Classic injection patterns
		"'; ", "; ", "';", // Statement termination
		"' OR ", " OR '", "' OR'", "1=1", "1='1'", // Boolean logic injection
		"' UNION ", " UNION ", "UNION SELECT", // Union-based injection
		"' AND ", " AND '", // Boolean logic
		"'='", "'<>'", "'!='", // Comparison operators

		// Advanced injection patterns
		"CHR(", "ASCII(", "CHAR(", "CONCAT(", // Function-based injection
		"SUBSTRING(", "SUBSTR(", "MID(", "LEFT(", "RIGHT(", // String manipulation
		"IF(", "CASE WHEN", "IIF(", // Conditional injection
		"CAST(", "CONVERT(", // Type conversion injection
		"@@",                                             // System variables
		"INFORMATION_SCHEMA", "SYS.TABLES", "SYSOBJECTS", // System catalogs

		// Hex/Unicode encoding attempts
		"0X", "\\U", "\\X", // Hex encoding
		"%2", "%3", "%5", "%7", // URL encoding
		"&#", // HTML entity encoding

		// Time-based blind injection
		"SLEEP(", "BENCHMARK(", "PG_SLEEP(", "WAITFOR DELAY",

		// Error-based injection indicators
		"EXTRACTVALUE(", "UPDATEXML(", "EXP(~(", "POLYGON(",

		// Suspicious system access patterns (not general SELECT patterns)
		"FROM INFORMATION_SCHEMA", "FROM SYS", "FROM DUAL",
	}

	for _, pattern := range injectionPatterns {
		if strings.Contains(upperQuery, pattern) {
			return fmt.Errorf("SQL injection pattern detected: %s", strings.ToLower(pattern))
		}
	}

	// Block dangerous characters that could be used for injection
	dangerousChars := []string{
		"'", "\"", // Quote characters
		";",        // Statement separator
		"--",       // SQL comments
		"/*", "*/", // Block comments
		"\\x00", "\\0", // Null bytes
		"\\n", "\\r", "\\t", // Control characters that could hide injection
		"$", "`", // Variable/command substitution
		"()", // Function calls without content
	}

	for _, char := range dangerousChars {
		// Count occurrences - some characters might be legitimate in small numbers
		count := strings.Count(query, char)
		if count > 0 {
			switch char {
			case "'", "\"":
				// Quotes should be balanced and not excessive
				if count > 4 || count%2 != 0 {
					return fmt.Errorf("suspicious quote usage detected")
				}
			case ";":
				// Multiple statements not allowed
				if count > 0 {
					return fmt.Errorf("multiple statements not allowed (semicolon detected)")
				}
			case "--", "/*", "*/":
				// Comments not allowed in dynamic queries
				return fmt.Errorf("SQL comments not allowed in dynamic queries")
			case "\\x00", "\\0":
				// Null bytes never allowed
				return fmt.Errorf("null bytes not allowed in SQL queries")
			default:
				// Other dangerous characters
				return fmt.Errorf("dangerous character detected: %s", char)
			}
		}
	}

	// Validate query length to prevent DoS attacks
	if len(query) > 10000 {
		return fmt.Errorf("query too long (max 10000 characters): %d", len(query))
	}

	// Ensure query starts with SELECT for read-only operations
	// This is a conservative approach - expand as needed for legitimate operations
	allowedStartPatterns := []string{
		"SELECT", "WITH", "EXPLAIN", "DESCRIBE", "SHOW",
	}

	startsWithAllowed := false
	for _, pattern := range allowedStartPatterns {
		if strings.HasPrefix(upperQuery, pattern+" ") || strings.HasPrefix(upperQuery, pattern+"(") {
			startsWithAllowed = true
			break
		}
	}

	if !startsWithAllowed {
		return fmt.Errorf("only SELECT, WITH, EXPLAIN, DESCRIBE, and SHOW queries are allowed. Query starts with: %s",
			strings.Fields(upperQuery)[0])
	}

	// Additional validation: ensure no nested queries that could bypass restrictions
	selectCount := strings.Count(upperQuery, "SELECT")
	if selectCount > 1 {
		// Allow CTE (WITH queries) that have multiple legitimate SELECT statements
		if strings.HasPrefix(upperQuery, "WITH ") {
			// WITH queries are allowed to have multiple SELECT statements
		} else {
			// For regular SELECT queries, only allow specific patterns
			allowed := strings.Contains(upperQuery, "UNION SELECT") ||
				strings.Contains(upperQuery, "EXISTS (SELECT") ||
				strings.Contains(upperQuery, "IN (SELECT")

			if !allowed {
				return fmt.Errorf("nested queries detected - potential injection attempt")
			}
		}
	}

	// Final check: ensure no obvious obfuscation attempts
	suspiciousPatterns := []string{
		"/**/",       // Empty comments used for obfuscation
		"''", "\"\"", // Empty strings
		"++", "--+", "+-", "-+", // Arithmetic obfuscation
		"  ", "   ", // Excessive whitespace
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(query, pattern) {
			return fmt.Errorf("suspicious obfuscation pattern detected: %s", pattern)
		}
	}

	return nil
}
