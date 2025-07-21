package database_management

import (
	"fmt"
	"testing"
)

// TestSQLInjectionPrevention tests the comprehensive SQL injection prevention
func TestSQLInjectionPrevention(t *testing.T) {
	tests := []struct {
		name        string
		query       string
		shouldAllow bool
		description string
	}{
		// Valid queries - should be allowed
		{
			name:        "Simple SELECT",
			query:       "SELECT * FROM users",
			shouldAllow: true,
			description: "Basic SELECT query should be allowed",
		},
		{
			name:        "SELECT with WHERE",
			query:       "SELECT name, email FROM users WHERE active = true",
			shouldAllow: true,
			description: "SELECT with WHERE clause should be allowed",
		},
		{
			name:        "WITH query",
			query:       "WITH active_users AS (SELECT * FROM users WHERE active = true) SELECT * FROM active_users",
			shouldAllow: true,
			description: "CTE queries should be allowed",
		},
		{
			name:        "EXPLAIN query",
			query:       "EXPLAIN SELECT * FROM users",
			shouldAllow: true,
			description: "EXPLAIN queries should be allowed",
		},
		{
			name:        "DESCRIBE query",
			query:       "DESCRIBE users",
			shouldAllow: true,
			description: "DESCRIBE queries should be allowed",
		},
		{
			name:        "SHOW query",
			query:       "SHOW TABLES",
			shouldAllow: true,
			description: "SHOW queries should be allowed",
		},

		// SQL Injection attacks - should be blocked
		{
			name:        "Classic SQL injection",
			query:       "SELECT * FROM users WHERE id = 1; DROP TABLE users; --",
			shouldAllow: false,
			description: "Classic injection with statement termination should be blocked",
		},
		{
			name:        "Boolean-based injection",
			query:       "SELECT * FROM users WHERE id = 1 OR 1=1",
			shouldAllow: false,
			description: "Boolean-based injection should be blocked",
		},
		{
			name:        "Union-based injection",
			query:       "SELECT * FROM users WHERE id = 1 UNION SELECT password FROM admin",
			shouldAllow: false,
			description: "Union-based injection should be blocked",
		},
		{
			name:        "Comment-based injection",
			query:       "SELECT * FROM users WHERE id = 1 -- AND active = true",
			shouldAllow: false,
			description: "Comment-based injection should be blocked",
		},
		{
			name:        "Time-based injection",
			query:       "SELECT * FROM users WHERE id = 1 AND SLEEP(5)",
			shouldAllow: false,
			description: "Time-based injection should be blocked",
		},
		{
			name:        "Function-based injection",
			query:       "SELECT * FROM users WHERE id = CONCAT('1', ' OR 1=1')",
			shouldAllow: false,
			description: "Function-based injection should be blocked",
		},

		// Dangerous operations - should be blocked
		{
			name:        "DROP TABLE",
			query:       "DROP TABLE users",
			shouldAllow: false,
			description: "DROP TABLE should be blocked",
		},
		{
			name:        "DELETE operation",
			query:       "DELETE FROM users WHERE id = 1",
			shouldAllow: false,
			description: "DELETE operations should be blocked",
		},
		{
			name:        "INSERT operation",
			query:       "INSERT INTO users (name) VALUES ('test')",
			shouldAllow: false,
			description: "INSERT operations should be blocked",
		},
		{
			name:        "UPDATE operation",
			query:       "UPDATE users SET name = 'hacked' WHERE id = 1",
			shouldAllow: false,
			description: "UPDATE operations should be blocked",
		},
		{
			name:        "ALTER TABLE",
			query:       "ALTER TABLE users ADD COLUMN hacked TEXT",
			shouldAllow: false,
			description: "ALTER TABLE should be blocked",
		},
		{
			name:        "CREATE USER",
			query:       "CREATE USER hacker WITH PASSWORD 'password'",
			shouldAllow: false,
			description: "CREATE USER should be blocked",
		},
		{
			name:        "GRANT privileges",
			query:       "GRANT ALL PRIVILEGES ON database.* TO 'hacker'",
			shouldAllow: false,
			description: "GRANT should be blocked",
		},

		// Encoding-based attacks - should be blocked
		{
			name:        "Hex encoding attack",
			query:       "SELECT * FROM users WHERE id = 0x31 OR 0x31=0x31",
			shouldAllow: false,
			description: "Hex encoding attacks should be blocked",
		},
		{
			name:        "URL encoding attack",
			query:       "SELECT * FROM users WHERE id = 1%20OR%201=1",
			shouldAllow: false,
			description: "URL encoding attacks should be blocked",
		},

		// System access attempts - should be blocked
		{
			name:        "Information schema access",
			query:       "SELECT * FROM INFORMATION_SCHEMA.TABLES",
			shouldAllow: false,
			description: "Information schema access should be blocked",
		},
		{
			name:        "System table access",
			query:       "SELECT * FROM SYS.TABLES",
			shouldAllow: false,
			description: "System table access should be blocked",
		},
		{
			name:        "File operations",
			query:       "SELECT * INTO OUTFILE '/etc/passwd' FROM users",
			shouldAllow: false,
			description: "File operations should be blocked",
		},

		// Edge cases
		{
			name:        "Empty query",
			query:       "",
			shouldAllow: false,
			description: "Empty query should be blocked",
		},
		{
			name:        "Very long query",
			query:       "SELECT " + string(make([]byte, 10001)),
			shouldAllow: false,
			description: "Overly long queries should be blocked",
		},
		{
			name:        "Query with null bytes",
			query:       "SELECT * FROM users\x00; DROP TABLE users;",
			shouldAllow: false,
			description: "Queries with null bytes should be blocked",
		},

		// Advanced injection patterns
		{
			name:        "Nested SELECT bypass attempt",
			query:       "SELECT * FROM users WHERE id IN (SELECT id FROM admin WHERE password = 'guess')",
			shouldAllow: true,
			description: "IN (SELECT) subqueries should be allowed as they are whitelisted",
		},
		{
			name:        "Obfuscated injection",
			query:       "SELECT/**/*/**/FROM/**/users/**/WHERE/**/1=1",
			shouldAllow: false,
			description: "Obfuscated injection should be blocked",
		},
		{
			name:        "Case variation injection",
			query:       "sElEcT * fRoM users WhErE 1=1",
			shouldAllow: false,
			description: "Case variation attacks should be blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSQLQuerySafety(tt.query)
			
			if tt.shouldAllow && err != nil {
				t.Errorf("Query should be allowed but was blocked: %s\nQuery: %s\nError: %v", 
					tt.description, tt.query, err)
			}
			
			if !tt.shouldAllow && err == nil {
				t.Errorf("Query should be blocked but was allowed: %s\nQuery: %s", 
					tt.description, tt.query)
			}

			// Additional logging for debugging
			if testing.Verbose() {
				if tt.shouldAllow {
					t.Logf("✅ ALLOWED: %s", tt.name)
				} else {
					t.Logf("🚫 BLOCKED: %s (reason: %v)", tt.name, err)
				}
			}
		})
	}
}

// TestSQLInjectionFuzzing performs fuzz-style testing with random dangerous patterns
func TestSQLInjectionFuzzing(t *testing.T) {
	// Common SQL injection payloads used in real attacks
	maliciousPayloads := []string{
		// Classic payloads
		"'; DROP TABLE users; --",
		"' OR '1'='1",
		"' OR 1=1 --",
		"admin'--",
		"admin'/*",
		"' OR '1'='1' --",
		"' OR '1'='1' /*",
		"'; INSERT INTO users VALUES ('hacker', 'password'); --",
		
		// Union-based
		"' UNION SELECT null, username, password FROM admin --",
		"' UNION ALL SELECT password FROM users --",
		"1' UNION SELECT @@version --",
		
		// Boolean-based
		"1' AND 1=1 --",
		"1' AND 1=2 --",
		"1' AND (SELECT COUNT(*) FROM users) > 0 --",
		
		// Time-based
		"1'; WAITFOR DELAY '00:00:05' --",
		"1' AND (SELECT SLEEP(5)) --",
		"1'; SELECT PG_SLEEP(5) --",
		
		// Error-based
		"1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e)) --",
		"1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
		
		// Stacked queries
		"1'; DELETE FROM users WHERE id=1; --",
		"1'; UPDATE users SET password='hacked'; --",
		"1'; ALTER TABLE users ADD COLUMN backdoor TEXT; --",
		
		// Advanced evasion
		"1'/**/OR/**/1=1/**/--",
		"1' /*!OR*/ 1=1 --",
		"1' %6fr 1=1 --", // Hex encoded OR
		"1'/**/union/**/select/**/null,user(),version()/**/--",
	}

	for i, payload := range maliciousPayloads {
		t.Run(fmt.Sprintf("Malicious_%d", i), func(t *testing.T) {
			err := validateSQLQuerySafety(payload)
			if err == nil {
				t.Errorf("Malicious SQL payload was not blocked:\nPayload: %s", payload)
			} else {
				t.Logf("✅ Successfully blocked payload: %s (reason: %v)", payload, err)
			}
		})
	}
}

// BenchmarkSQLValidation benchmarks the SQL validation performance
func BenchmarkSQLValidation(b *testing.B) {
	testQuery := "SELECT name, email FROM users WHERE active = true AND created_at > NOW() - INTERVAL '30 days'"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validateSQLQuerySafety(testQuery)
	}
}

// BenchmarkSQLValidationMalicious benchmarks validation with malicious input
func BenchmarkSQLValidationMalicious(b *testing.B) {
	maliciousQuery := "SELECT * FROM users WHERE id = 1' OR '1'='1' UNION SELECT password FROM admin --"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validateSQLQuerySafety(maliciousQuery)
	}
}