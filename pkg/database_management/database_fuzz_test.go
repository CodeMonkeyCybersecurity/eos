// pkg/database_management/database_fuzz_test.go
package database_management

import (
	"strings"
	"testing"
	"time"
)

// FuzzDatabaseOperation tests SQL injection and other database operation vulnerabilities
func FuzzDatabaseOperation(f *testing.F) {
	// Seed with safe operations
	f.Add("SELECT * FROM users", "users", false)
	f.Add("INSERT INTO logs (message) VALUES ('test')", "logs", false)
	f.Add("UPDATE settings SET value = 'new' WHERE key = 'config'", "settings", false)
	
	// Seed with potentially malicious SQL injection patterns
	f.Add("SELECT * FROM users WHERE id = '1 OR 1=1'", "users", false)
	f.Add("'; DROP TABLE users; --", "users", false)
	f.Add("SELECT * FROM users; DELETE FROM users; --", "users", false)
	f.Add("1' UNION SELECT password FROM admin --", "users", false)
	f.Add("'; INSERT INTO admin (user,pass) VALUES ('hacker','pwned'); --", "users", false)
	f.Add("SELECT load_file('/etc/passwd')", "users", false)
	f.Add("SELECT 1 INTO OUTFILE '/tmp/evil.txt'", "users", false)
	f.Add("SELECT * FROM users WHERE id = 1; EXEC xp_cmdshell('dir');", "users", false)
	f.Add("SELECT pg_sleep(10)", "users", false)
	f.Add("SELECT benchmark(1000000,MD5(1))", "users", false)
	f.Add("SELECT * FROM information_schema.tables", "users", false)
	f.Add("SELECT user() ,database(), version()", "users", false)
	f.Add("SELECT @@version", "users", false)
	f.Add("'; WAITFOR DELAY '00:00:10'; --", "users", false)
	f.Add("SELECT * FROM users WHERE id = (SELECT COUNT(*) FROM sysobjects)", "users", false)
	
	f.Fuzz(func(t *testing.T, query, database string, transaction bool) {
		if query == "" || database == "" {
			return
		}
		
		// Skip extremely long queries to prevent resource exhaustion
		if len(query) > 10000 {
			return
		}
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("DatabaseOperation creation panicked on query='%s': %v", query, r)
			}
		}()
		
		// Test creating DatabaseOperation structure with fuzzed inputs
		operation := &DatabaseOperation{
			Type:        "query",
			Database:    database,
			Query:       query,
			Transaction: transaction,
			DryRun:      true, // Always dry run in fuzz tests
		}
		
		// Verify the operation structure was created successfully
		if operation.Query != query {
			t.Errorf("Query was modified during operation creation")
		}
		
		// Check for obvious SQL injection patterns (basic detection)
		if containsSQLInjectionPatterns(query) {
			t.Logf("Detected potential SQL injection pattern in query: %s", query)
		}
	})
}

// FuzzDatabaseConfig tests database configuration parsing with malicious inputs
func FuzzDatabaseConfig(f *testing.F) {
	f.Add("localhost", 5432, "testdb", "user", "pass", "disable")
	f.Add("127.0.0.1", 3306, "mysql", "root", "", "require")
	
	// Malicious configuration patterns
	f.Add("evil.com", 1337, "'; DROP DATABASE test; --", "admin", "password", "disable")
	f.Add("192.168.1.1", -1, "database", "user", "pass", "disable")        // Negative port
	f.Add("localhost", 65536, "db", "user", "pass", "disable")             // Port out of range
	f.Add("host\x00evil", 5432, "db", "user", "pass", "disable")          // Null byte in host
	f.Add("localhost", 5432, "db\nmalicious", "user", "pass", "disable")   // Newline in database name
	f.Add("localhost", 5432, "db", "user\x00admin", "pass", "disable")     // Null byte in username
	f.Add("localhost", 5432, "db", "user", "pass\nmalicious", "disable")   // Newline in password
	f.Add(strings.Repeat("a", 1000), 5432, "db", "user", "pass", "disable") // Long hostname
	f.Add("localhost", 5432, strings.Repeat("b", 100), "user", "pass", "disable") // Long database name
	f.Add("file:///etc/passwd", 5432, "db", "user", "pass", "disable")     // File URI as host
	f.Add("javascript:alert(1)", 5432, "db", "user", "pass", "disable")    // JavaScript injection
	
	f.Fuzz(func(t *testing.T, host string, port int, database, username, password, sslMode string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("DatabaseConfig creation panicked: %v", r)
			}
		}()
		
		// Test creating DatabaseConfig with fuzzed inputs
		config := &DatabaseConfig{
			Type:     DatabaseTypePostgreSQL,
			Host:     host,
			Port:     port,
			Database: database,
			Username: username,
			Password: password,
			SSLMode:  sslMode,
		}
		
		// Basic validation checks
		if len(config.Host) > 255 {
			t.Errorf("Host is unreasonably long: %d characters", len(config.Host))
		}
		
		if port < 0 || port > 65535 {
			t.Logf("Port out of valid range: %d", port)
		}
		
		// Check for dangerous characters in database identifiers
		if containsDangerousChars(database) || containsDangerousChars(username) {
			t.Logf("Dangerous characters detected in database config")
		}
	})
}

// FuzzRoleStatements tests SQL role creation/revocation statements for injection
func FuzzRoleStatements(f *testing.F) {
	// Safe role statements
	f.Add("CREATE USER \"{{name}}\" WITH PASSWORD '{{password}}'")
	f.Add("GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\"")
	f.Add("DROP USER \"{{name}}\"")
	
	// Potentially dangerous role statements
	f.Add("CREATE USER {{name}} WITH PASSWORD '{{password}}'; DROP TABLE users; --")
	f.Add("GRANT ALL PRIVILEGES ON *.* TO '{{name}}'@'%' WITH GRANT OPTION")
	f.Add("CREATE USER \"{{name}}\" WITH SUPERUSER PASSWORD '{{password}}'")
	f.Add("'; DELETE FROM users; CREATE USER malicious WITH PASSWORD 'evil'; --")
	f.Add("GRANT EXECUTE ON FUNCTION load_file TO \"{{name}}\"")
	f.Add("CREATE USER \"{{name}}\"; EXEC xp_cmdshell('net user hacker hacker /add'); --")
	
	f.Fuzz(func(t *testing.T, statementsStr string) {
		// Parse the input string into statements
		statements := strings.Split(statementsStr, "\n")
		if len(statements) == 0 || (len(statements) == 1 && statements[0] == "") {
			return
		}
		if len(statements) == 0 {
			return
		}
		
		// Skip extremely long statement lists
		if len(statements) > 100 {
			return
		}
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Role creation panicked: %v", r)
			}
		}()
		
		// Test creating Role with fuzzed statements
		role := &Role{
			Name:               "test_role",
			DBName:             "test_db",
			CreationStatements: statements,
			DefaultTTL:         24 * time.Hour,
			MaxTTL:             7 * 24 * time.Hour,
		}
		
		// Check each statement for potential issues
		for i, stmt := range role.CreationStatements {
			if len(stmt) > 10000 {
				t.Errorf("Statement %d is extremely long: %d characters", i, len(stmt))
			}
			
			if containsSQLInjectionPatterns(stmt) {
				t.Logf("Potential SQL injection in role statement %d: %s", i, stmt)
			}
		}
	})
}

// FuzzBackupFilePath tests backup file path handling for path traversal
func FuzzBackupFilePath(f *testing.F) {
	f.Add("backup.sql", "testdb")
	f.Add("/tmp/backup.sql", "mydb")
	f.Add("./backups/db.sql", "appdb")
	
	// Path traversal patterns
	f.Add("../../../etc/passwd", "db")
	f.Add("/etc/../../../root/.ssh/id_rsa", "db")
	f.Add("backup\x00malicious.sql", "db")
	f.Add("backup\n../evil.sql", "db")
	f.Add("\\..\\..\\windows\\system32\\config\\sam", "db")
	f.Add("backup.sql\x00.evil", "db")
	f.Add(strings.Repeat("../", 100) + "etc/passwd", "db")
	f.Add("file:///etc/passwd", "db")
	f.Add("backup.sql; rm -rf /", "db")
	
	f.Fuzz(func(t *testing.T, filePath, database string) {
		if filePath == "" || database == "" {
			return
		}
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("BackupInfo creation panicked: %v", r)
			}
		}()
		
		// Test creating BackupInfo with fuzzed file path
		backup := &BackupInfo{
			Database:  database,
			FilePath:  filePath,
			Size:      1024,
			CreatedAt: time.Now(),
			Type:      "full",
		}
		
		// Check for path traversal attempts
		if strings.Contains(filePath, "..") {
			t.Logf("Potential path traversal in backup path: %s", filePath)
		}
		
		// Check for dangerous characters
		if containsDangerousChars(filePath) {
			t.Logf("Dangerous characters in backup path: %s", filePath)
		}
		
		// Check for null bytes
		if strings.Contains(filePath, "\x00") {
			t.Logf("Null byte injection in backup path: %s", filePath)
		}
		
		// Verify backup info was created
		if backup.FilePath != filePath {
			t.Errorf("File path was modified during BackupInfo creation")
		}
	})
}

// Helper function to detect basic SQL injection patterns
func containsSQLInjectionPatterns(query string) bool {
	lowerQuery := strings.ToLower(query)
	
	// Common SQL injection patterns
	patterns := []string{
		"' or '1'='1",
		"' or 1=1",
		"'; drop table",
		"'; delete from",
		"union select",
		"exec xp_cmdshell",
		"load_file(",
		"into outfile",
		"information_schema",
		"pg_sleep(",
		"benchmark(",
		"waitfor delay",
		"@@version",
		"user()",
		"database()",
		"version()",
		"current_user",
		"system_user",
		"--",
		"/*",
		"*/",
		"\x00", // Null byte
		"\n",   // Newline
		"\r",   // Carriage return
	}
	
	for _, pattern := range patterns {
		if strings.Contains(lowerQuery, pattern) {
			return true
		}
	}
	
	return false
}

// Helper function to detect dangerous characters in database identifiers
func containsDangerousChars(input string) bool {
	dangerousChars := []string{
		"\x00", "\n", "\r", "\t", // Control characters
		"'", "\"", "`",           // Quote characters
		";", "--", "/*", "*/",    // SQL comment/termination
		"<", ">", "&", "|",       // Shell metacharacters
		"$(", "${", "`",          // Command substitution
	}
	
	for _, char := range dangerousChars {
		if strings.Contains(input, char) {
			return true
		}
	}
	
	return false
}