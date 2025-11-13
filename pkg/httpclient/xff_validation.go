// pkg/httpclient/xff_validation.go
package httpclient

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// TrustedProxyValidator validates X-Forwarded-For headers against trusted proxies
type TrustedProxyValidator struct {
	trustedProxies []*net.IPNet
}

// NewTrustedProxyValidator creates a validator with the given trusted proxy CIDRs
// Example: NewTrustedProxyValidator([]string{"10.0.0.0/8", "192.168.1.0/24"})
func NewTrustedProxyValidator(trustedCIDRs []string) (*TrustedProxyValidator, error) {
	validator := &TrustedProxyValidator{
		trustedProxies: make([]*net.IPNet, 0, len(trustedCIDRs)),
	}

	for _, cidr := range trustedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
		}
		validator.trustedProxies = append(validator.trustedProxies, ipNet)
	}

	return validator, nil
}

// GetClientIP extracts the real client IP from the request
// SECURITY: Only trusts X-Forwarded-For if the immediate client is a trusted proxy
// This prevents IP spoofing attacks where malicious clients set X-Forwarded-For
//
// Algorithm:
// 1. If immediate client is NOT in trusted proxies → return immediate client IP
// 2. If immediate client IS trusted → check X-Forwarded-For header
// 3. Return rightmost non-trusted IP in X-Forwarded-For chain
//
// Example:
//
//	X-Forwarded-For: client, proxy1, proxy2
//	Immediate client: proxy2 (trusted)
//	→ Returns "client" (first non-trusted IP)
func (v *TrustedProxyValidator) GetClientIP(r *http.Request) (string, error) {
	// Get immediate client IP from RemoteAddr
	immediateIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", fmt.Errorf("invalid RemoteAddr: %w", err)
	}

	clientIP := net.ParseIP(immediateIP)
	if clientIP == nil {
		return "", fmt.Errorf("invalid IP address: %s", immediateIP)
	}

	// Check if immediate client is a trusted proxy
	isTrusted := v.isTrustedProxy(clientIP)

	// If immediate client is NOT trusted, don't trust X-Forwarded-For
	// (could be spoofed by attacker)
	if !isTrusted {
		return immediateIP, nil
	}

	// Immediate client is trusted - check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		// No X-Forwarded-For header, use immediate client
		return immediateIP, nil
	}

	// Parse X-Forwarded-For chain (comma-separated list)
	// Format: "client, proxy1, proxy2"
	// We want the rightmost non-trusted IP (the actual client)
	ips := strings.Split(xff, ",")

	// Walk backwards through the chain to find first non-trusted IP
	for i := len(ips) - 1; i >= 0; i-- {
		ipStr := strings.TrimSpace(ips[i])
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue // Skip invalid IPs
		}

		// Found first non-trusted IP - this is the real client
		if !v.isTrustedProxy(ip) {
			return ipStr, nil
		}
	}

	// All IPs in X-Forwarded-For are trusted proxies
	// Fall back to immediate client IP
	return immediateIP, nil
}

// isTrustedProxy checks if an IP is in the trusted proxy list
func (v *TrustedProxyValidator) isTrustedProxy(ip net.IP) bool {
	for _, ipNet := range v.trustedProxies {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateXForwardedFor is a convenience function for simple validation
// Returns the real client IP or an error if validation fails
//
// SECURITY: This function enforces that X-Forwarded-For is only trusted
// when the immediate client is in the trusted proxy list.
//
// Usage:
//
//	validator, _ := NewTrustedProxyValidator([]string{"10.0.0.0/8"})
//	clientIP, err := validator.ValidateXForwardedFor(r)
func (v *TrustedProxyValidator) ValidateXForwardedFor(r *http.Request) (string, error) {
	return v.GetClientIP(r)
}

// DefaultTrustedProxies returns common private network ranges for trusted proxies
// Use this when your reverse proxies are on private networks
//
// Includes:
// - 10.0.0.0/8 (private network)
// - 172.16.0.0/12 (private network)
// - 192.168.0.0/16 (private network)
// - 127.0.0.0/8 (localhost)
func DefaultTrustedProxies() []string {
	return []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}
}
