package hecate

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// ValidateIPAddress validates an IP address
func ValidateIPAddress(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address cannot be empty")
	}

	// Parse IP address
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address format: %s", ip)
	}

	// Additional checks for edge cases
	if strings.HasPrefix(ip, "0.") && ip != "0.0.0.0" {
		return fmt.Errorf("invalid IP address: leading zeros not allowed")
	}

	// Check for reserved/invalid ranges
	if ip == "0.0.0.0" {
		return fmt.Errorf("IP address 0.0.0.0 is not allowed")
	}

	return nil
}

// ValidatePort validates a port number
func ValidatePort(port string) error {
	if port == "" {
		return fmt.Errorf("port cannot be empty")
	}

	// Check if numeric
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port must be numeric: %s", port)
	}

	// Check port range
	if portNum <= 0 || portNum > 65535 {
		return fmt.Errorf("port must be between 1 and 65535: %d", portNum)
	}

	return nil
}

// ValidateDomain validates a domain name
func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	// Basic length check
	if len(domain) > 253 {
		return fmt.Errorf("domain name too long: %d characters (max 253)", len(domain))
	}

	// Check for valid domain format
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format: %s", domain)
	}

	// Check for dangerous characters
	dangerousChars := []string{";", "&", "|", "`", "$", "(", ")", "{", "}", "[", "]", "<", ">", "\"", "'"}
	for _, char := range dangerousChars {
		if strings.Contains(domain, char) {
			return fmt.Errorf("domain contains dangerous character: %s", char)
		}
	}

	return nil
}

// ValidateUpstream validates an upstream address
func ValidateUpstream(upstream string) error {
	if upstream == "" {
		return fmt.Errorf("upstream cannot be empty")
	}

	// Split host:port
	parts := strings.Split(upstream, ":")
	if len(parts) != 2 {
		return fmt.Errorf("upstream must be in format host:port: %s", upstream)
	}

	host, port := parts[0], parts[1]

	// Validate host (can be IP or domain)
	if net.ParseIP(host) == nil {
		// If not IP, validate as domain
		if err := ValidateDomain(host); err != nil {
			return fmt.Errorf("invalid upstream host: %w", err)
		}
	} else {
		// If IP, validate it
		if err := ValidateIPAddress(host); err != nil {
			return fmt.Errorf("invalid upstream IP: %w", err)
		}
	}

	// Validate port
	if err := ValidatePort(port); err != nil {
		return fmt.Errorf("invalid upstream port: %w", err)
	}

	return nil
}

// ValidateRouteInput validates route creation input
func ValidateRouteInput(domain string, upstreams []string) error {
	// Validate domain
	if err := ValidateDomain(domain); err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}

	// Validate upstreams
	if len(upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}

	for i, upstream := range upstreams {
		if err := ValidateUpstream(upstream); err != nil {
			return fmt.Errorf("invalid upstream %d: %w", i+1, err)
		}
	}

	return nil
}

// SanitizeInput sanitizes user input to prevent injection attacks
func SanitizeInput(input string) string {
	// Remove dangerous characters
	dangerousChars := []string{";", "&", "|", "`", "$", "(", ")", "{", "}", "[", "]", "<", ">", "\"", "'", "\\"}
	sanitized := input
	for _, char := range dangerousChars {
		sanitized = strings.ReplaceAll(sanitized, char, "")
	}

	// Remove control characters
	sanitized = regexp.MustCompile(`[\x00-\x1f\x7f]`).ReplaceAllString(sanitized, "")

	// Trim whitespace
	sanitized = strings.TrimSpace(sanitized)

	return sanitized
}

// ValidatePathTraversal checks for path traversal attempts
func ValidatePathTraversal(path string) error {
	// Check for path traversal patterns
	dangerousPatterns := []string{
		"..",
		"./",
		"../",
		"..\\",
		".\\",
		"..\\",
		"/etc/",
		"/var/",
		"/tmp/",
		"/root/",
		"/home/",
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerPath, pattern) {
			return fmt.Errorf("path contains dangerous pattern: %s", pattern)
		}
	}

	return nil
}

// ValidateEnvironmentVariable validates environment variable values
func ValidateEnvironmentVariable(name, value string) error {
	// Check for injection attempts in environment variables
	if strings.Contains(value, "../") || strings.Contains(value, "..\\") {
		return fmt.Errorf("environment variable %s contains path traversal: %s", name, value)
	}

	// Check for command injection
	if strings.Contains(value, ";") || strings.Contains(value, "&") || strings.Contains(value, "|") {
		return fmt.Errorf("environment variable %s contains command injection: %s", name, value)
	}

	return nil
}

// IsReservedDomain checks if a domain is reserved for SSO/auth infrastructure
// These domains should NEVER be protected with forward_auth to prevent lockout
func IsReservedDomain(domain string) bool {
	// Reserved subdomains/prefixes for Authentik SSO
	reservedPrefixes := []string{
		"hera.",      // Authentik SSO provider
		"auth.",      // Generic auth subdomain
		"login.",     // Generic login subdomain
		"sso.",       // Generic SSO subdomain
		"authentik.", // Explicit Authentik subdomain
	}

	lowerDomain := strings.ToLower(domain)
	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(lowerDomain, prefix) {
			return true
		}
	}

	return false
}

// ValidateRoute validates a complete route configuration
func ValidateRoute(route *Route) error {
	if route == nil {
		return fmt.Errorf("route cannot be nil")
	}

	// Validate domain
	if err := ValidateDomain(route.Domain); err != nil {
		return fmt.Errorf("invalid route domain: %w", err)
	}

	// Check for reserved domain with auth enabled
	if route.RequireAuth && IsReservedDomain(route.Domain) {
		return fmt.Errorf("cannot enable authentication on reserved domain '%s' - this prevents access to the SSO provider", route.Domain)
	}

	// Validate upstream
	if route.Upstream == nil {
		return fmt.Errorf("route upstream cannot be nil")
	}

	if err := ValidateUpstream(route.Upstream.URL); err != nil {
		return fmt.Errorf("invalid route upstream: %w", err)
	}

	// Validate headers
	for key, value := range route.Headers {
		if strings.ContainsAny(key, ";|&$<>\"'") {
			return fmt.Errorf("header name contains dangerous characters: %s", key)
		}
		if strings.ContainsAny(value, ";|&$<>\"'") {
			return fmt.Errorf("header value contains dangerous characters: %s", value)
		}
	}

	return nil
}