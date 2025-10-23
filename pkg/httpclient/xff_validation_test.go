// pkg/httpclient/xff_validation_test.go
package httpclient

import (
	"net/http"
	"testing"
)

func TestGetClientIP_NoXFFHeader(t *testing.T) {
	validator, err := NewTrustedProxyValidator([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	req := &http.Request{
		RemoteAddr: "192.168.1.100:12345",
		Header:     http.Header{},
	}

	clientIP, err := validator.GetClientIP(req)
	if err != nil {
		t.Fatalf("GetClientIP failed: %v", err)
	}

	expected := "192.168.1.100"
	if clientIP != expected {
		t.Errorf("Expected %s, got %s", expected, clientIP)
	}
}

func TestGetClientIP_UntrustedClient(t *testing.T) {
	validator, err := NewTrustedProxyValidator([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Client is NOT in trusted proxy list - should ignore X-Forwarded-For
	req := &http.Request{
		RemoteAddr: "192.168.1.100:12345",
		Header: http.Header{
			"X-Forwarded-For": []string{"1.2.3.4, 5.6.7.8"},
		},
	}

	clientIP, err := validator.GetClientIP(req)
	if err != nil {
		t.Fatalf("GetClientIP failed: %v", err)
	}

	// Should return RemoteAddr, ignoring spoofed X-Forwarded-For
	expected := "192.168.1.100"
	if clientIP != expected {
		t.Errorf("Expected %s (ignored spoofed XFF), got %s", expected, clientIP)
	}
}

func TestGetClientIP_TrustedProxy(t *testing.T) {
	validator, err := NewTrustedProxyValidator([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Client IS in trusted proxy list - should trust X-Forwarded-For
	req := &http.Request{
		RemoteAddr: "10.0.0.5:12345", // Trusted proxy
		Header: http.Header{
			"X-Forwarded-For": []string{"203.0.113.1, 10.0.0.2, 10.0.0.5"},
		},
	}

	clientIP, err := validator.GetClientIP(req)
	if err != nil {
		t.Fatalf("GetClientIP failed: %v", err)
	}

	// Should return the rightmost non-trusted IP (real client)
	expected := "203.0.113.1"
	if clientIP != expected {
		t.Errorf("Expected %s (real client), got %s", expected, clientIP)
	}
}

func TestGetClientIP_AllTrustedProxies(t *testing.T) {
	validator, err := NewTrustedProxyValidator([]string{"10.0.0.0/8", "203.0.113.0/24"})
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// All IPs in chain are trusted - should fall back to RemoteAddr
	req := &http.Request{
		RemoteAddr: "10.0.0.5:12345",
		Header: http.Header{
			"X-Forwarded-For": []string{"203.0.113.1, 10.0.0.2, 10.0.0.5"},
		},
	}

	clientIP, err := validator.GetClientIP(req)
	if err != nil {
		t.Fatalf("GetClientIP failed: %v", err)
	}

	// Should fall back to RemoteAddr
	expected := "10.0.0.5"
	if clientIP != expected {
		t.Errorf("Expected %s (fallback), got %s", expected, clientIP)
	}
}

func TestGetClientIP_InvalidXFF(t *testing.T) {
	validator, err := NewTrustedProxyValidator([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// X-Forwarded-For contains invalid IP
	req := &http.Request{
		RemoteAddr: "10.0.0.5:12345",
		Header: http.Header{
			"X-Forwarded-For": []string{"invalid-ip, 10.0.0.2"},
		},
	}

	clientIP, err := validator.GetClientIP(req)
	if err != nil {
		t.Fatalf("GetClientIP failed: %v", err)
	}

	// Should skip invalid IP and return RemoteAddr (all others are trusted)
	expected := "10.0.0.5"
	if clientIP != expected {
		t.Errorf("Expected %s (skipped invalid), got %s", expected, clientIP)
	}
}

func TestNewTrustedProxyValidator_InvalidCIDR(t *testing.T) {
	_, err := NewTrustedProxyValidator([]string{"invalid-cidr"})
	if err == nil {
		t.Error("Expected error for invalid CIDR, got nil")
	}
}

func TestDefaultTrustedProxies(t *testing.T) {
	proxies := DefaultTrustedProxies()
	if len(proxies) != 4 {
		t.Errorf("Expected 4 default proxies, got %d", len(proxies))
	}

	// Verify they're all valid CIDRs
	_, err := NewTrustedProxyValidator(proxies)
	if err != nil {
		t.Errorf("Default proxies should be valid CIDRs: %v", err)
	}
}

// Security test: Verify that spoofed X-Forwarded-For is rejected
func TestSecurity_SpoofedXFF(t *testing.T) {
	validator, err := NewTrustedProxyValidator([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Attacker tries to spoof X-Forwarded-For from untrusted network
	req := &http.Request{
		RemoteAddr: "203.0.113.50:12345", // Attacker's real IP (NOT trusted)
		Header: http.Header{
			// Attacker claims to be from localhost to bypass restrictions
			"X-Forwarded-For": []string{"shared.GetInternalHostname"},
		},
	}

	clientIP, err := validator.GetClientIP(req)
	if err != nil {
		t.Fatalf("GetClientIP failed: %v", err)
	}

	// SECURITY: Should return attacker's real IP, not spoofed value
	expected := "203.0.113.50"
	if clientIP != expected {
		t.Errorf("SECURITY FAIL: Accepted spoofed XFF. Expected %s, got %s", expected, clientIP)
	}
}
