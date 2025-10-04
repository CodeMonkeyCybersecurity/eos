// pkg/httpclient/ssrf_protection.go
package httpclient

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// SSRFProtection provides protection against Server-Side Request Forgery attacks
type SSRFProtection struct {
	AllowedDomains []string // Whitelist of allowed domains (optional)
	BlockPrivateIP bool     // Block private/internal IPs
	RequireHTTPS   bool     // Require HTTPS URLs
}

// DefaultSSRFProtection returns a secure default SSRF protection configuration
func DefaultSSRFProtection() *SSRFProtection {
	return &SSRFProtection{
		BlockPrivateIP: true,
		RequireHTTPS:   true,
	}
}

// ValidateURL checks if a URL is safe to request (not SSRF-vulnerable)
// SECURITY: Prevents access to internal IPs, cloud metadata, localhost
func (s *SSRFProtection) ValidateURL(urlStr string) error {
	// Parse URL
	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// SECURITY: Require HTTPS if configured
	if s.RequireHTTPS && u.Scheme != "https" {
		return fmt.Errorf("only HTTPS URLs allowed, got scheme: %s", u.Scheme)
	}

	// SECURITY: Block non-HTTP(S) schemes (file://, ftp://, gopher://, etc.)
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("only HTTP(S) URLs allowed, got scheme: %s", u.Scheme)
	}

	// Extract hostname
	hostname := u.Hostname()
	if hostname == "" {
		return fmt.Errorf("URL missing hostname")
	}

	// SECURITY: Check domain whitelist if configured
	if len(s.AllowedDomains) > 0 {
		allowed := false
		for _, domain := range s.AllowedDomains {
			if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("domain not in allowlist: %s", hostname)
		}
	}

	// SECURITY: Block private/internal IPs if configured
	if s.BlockPrivateIP {
		if err := s.checkPrivateIP(hostname); err != nil {
			return err
		}
	}

	return nil
}

// checkPrivateIP validates that hostname does not resolve to private/internal IP
func (s *SSRFProtection) checkPrivateIP(hostname string) error {
	// SECURITY: Block localhost variants
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		return fmt.Errorf("access to localhost blocked")
	}

	// SECURITY: Block cloud metadata endpoints
	cloudMetadataHosts := []string{
		"169.254.169.254",     // AWS, Azure, GCP metadata (IPv4)
		"fd00:ec2::254",       // AWS metadata (IPv6)
		"metadata.google.internal", // GCP metadata
		"169.254.169.253",     // AWS IMDSv2 token endpoint
	}
	for _, blocked := range cloudMetadataHosts {
		if hostname == blocked {
			return fmt.Errorf("access to cloud metadata endpoint blocked: %s", hostname)
		}
	}

	// Parse IP if it's an IP address
	ip := net.ParseIP(hostname)
	if ip != nil {
		return s.validateIP(ip)
	}

	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		// DNS lookup failed - this might be intentional SSRF evasion
		// Better to fail closed
		return fmt.Errorf("DNS lookup failed (potential SSRF): %w", err)
	}

	// Check all resolved IPs
	for _, ip := range ips {
		if err := s.validateIP(ip); err != nil {
			return fmt.Errorf("hostname %s resolves to blocked IP %s: %w", hostname, ip, err)
		}
	}

	return nil
}

// validateIP checks if an IP address is private/internal
func (s *SSRFProtection) validateIP(ip net.IP) error {
	// SECURITY: Block loopback addresses (127.0.0.0/8, ::1)
	if ip.IsLoopback() {
		return fmt.Errorf("loopback IP blocked: %s", ip)
	}

	// SECURITY: Block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
	if ip.IsPrivate() {
		return fmt.Errorf("private IP blocked: %s", ip)
	}

	// SECURITY: Block link-local addresses (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() {
		return fmt.Errorf("link-local IP blocked: %s", ip)
	}

	// SECURITY: Block multicast addresses
	if ip.IsMulticast() {
		return fmt.Errorf("multicast IP blocked: %s", ip)
	}

	// SECURITY: Block unspecified addresses (0.0.0.0, ::)
	if ip.IsUnspecified() {
		return fmt.Errorf("unspecified IP blocked: %s", ip)
	}

	// Additional checks for IPv4
	if ip.To4() != nil {
		// Block carrier-grade NAT (100.64.0.0/10)
		if ip[0] == 100 && (ip[1]&0xC0) == 64 {
			return fmt.Errorf("carrier-grade NAT IP blocked: %s", ip)
		}

		// Block 0.0.0.0/8 (current network)
		if ip[0] == 0 {
			return fmt.Errorf("current network IP blocked: %s", ip)
		}

		// Block 192.0.0.0/24 (IETF protocol assignments)
		if ip[0] == 192 && ip[1] == 0 && ip[2] == 0 {
			return fmt.Errorf("IETF protocol IP blocked: %s", ip)
		}
	}

	return nil
}

// ValidateAndGet is a helper that validates URL and returns it if safe
func (s *SSRFProtection) ValidateAndGet(urlStr string) (string, error) {
	if err := s.ValidateURL(urlStr); err != nil {
		return "", err
	}
	return urlStr, nil
}
