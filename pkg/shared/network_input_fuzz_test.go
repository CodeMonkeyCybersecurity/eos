package shared

import (
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzURLValidation tests URL validation for injection and bypass attacks
func FuzzURLValidation(f *testing.F) {
	// Add seed corpus with URL attack vectors
	seeds := []string{
		// SSRF attacks
		"http://169.254.169.254/metadata/",
		"http://localhost:22/",
		"http://shared.GetInternalHostname:8080/admin",
		"http://0.0.0.0:3306/",
		"file:///etc/passwd",
		"ftp://internal.server/",

		// URL bypass techniques
		"http://evil.com@good.com/",
		"http://good.com.evil.com/",
		"http://good%2ecom/",
		"http://127.1/",
		"http://0x7f000001/", // Hex encoding
		"http://2130706433/", // Decimal encoding

		// Protocol confusion
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:Execute(malicious)",
		"mailto:user@evil.com?cc=admin@target.com",

		// Port scanning
		"http://target.com:22/",
		"http://target.com:3389/",
		"http://target.com:445/",
		"http://target.com:135/",

		// Unicode attacks
		"http://аррӏе.com/",           // Cyrillic characters that look like apple.com
		"http://google.com\u2024com/", // Unicode confusion
		"http://goog1е.com/",          // Cyrillic 'е' instead of Latin 'e'

		// Long URLs (DoS)
		"http://example.com/" + strings.Repeat("A", 10000),
		"http://" + strings.Repeat("A", 1000) + ".com/",

		// Null byte injection
		"http://example.com\x00.evil.com/",
		"http://example.com/path\x00malicious",

		// Valid URLs
		"https://example.com/",
		"http://localhost/",
		"https://api.example.com/v1/endpoint",
		"",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, rawURL string) {
		// Test URL validation
		isValid := validateURL(rawURL)
		_ = isValid

		// Test URL parsing
		parsed, err := parseURL(rawURL)
		if err != nil {
			// Invalid URLs should be rejected gracefully
			return
		}

		// Test hostname validation
		if parsed.Host != "" {
			isValidHost := validateHostname(parsed.Host)
			_ = isValidHost
		}

		// Test scheme validation
		isValidScheme := validateURLScheme(parsed.Scheme)
		_ = isValidScheme

		// Test URL sanitization
		sanitized := sanitizeURL(rawURL)
		if !utf8.ValidString(sanitized) {
			t.Error("Sanitized URL is not valid UTF-8")
		}

		// Test SSRF protection
		if isValid {
			isSafe := isSSRFSafeURL(rawURL)
			_ = isSafe
		}

		// Test URL normalization
		normalized := normalizeURL(rawURL)
		if len(normalized) > len(rawURL)*2 {
			t.Error("Normalized URL significantly larger than original")
		}
	})
}

// FuzzHTTPHeaders tests HTTP header validation for injection attacks
func FuzzHTTPHeaders(f *testing.F) {
	seeds := []string{
		// Header injection
		"value\r\nX-Injected: evil",
		"value\nSet-Cookie: session=hijacked",
		"value\r\n\r\n<script>alert(1)</script>",

		// Command injection in headers
		"value; rm -rf /",
		"value | cat /etc/passwd",
		"$(whoami)",
		"`id`",

		// XSS in headers
		"<script>alert(1)</script>",
		"javascript:alert(document.cookie)",
		"'><script>alert(1)</script>",

		// Unicode attacks
		"value\u000aX-Evil: injected",
		"value\u000dX-Evil: injected",
		"value\u2028X-Evil: injected",
		"value\u2029X-Evil: injected",

		// Long headers (DoS)
		strings.Repeat("A", 8192),
		strings.Repeat("A", 65536),

		// Binary data
		"value\x00\x01\x02",
		"\x7f\x80\x81",

		// Valid headers
		"application/json",
		"text/html; charset=utf-8",
		"Bearer token123",
		"gzip, deflate",
		"",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, headerValue string) {
		// Test header validation
		isValid := validateHTTPHeader(headerValue)
		_ = isValid

		// Test header sanitization
		sanitized := sanitizeHTTPHeader(headerValue)

		// Verify sanitization removes dangerous characters
		if strings.Contains(sanitized, "\r") || strings.Contains(sanitized, "\n") {
			t.Error("Sanitized header contains line breaks")
		}

		if strings.Contains(sanitized, "\x00") {
			t.Error("Sanitized header contains null bytes")
		}

		// Test header length validation
		if len(sanitized) > 8192 {
			t.Error("Sanitized header exceeds maximum length")
		}

		// Test header encoding
		encoded := encodeHTTPHeader(headerValue)
		if !isValidHTTPHeaderEncoding(encoded) {
			t.Error("Header encoding is invalid")
		}
	})
}

// FuzzQueryParameters tests query parameter validation for injection attacks
func FuzzQueryParameters(f *testing.F) {
	seeds := []string{
		// SQL injection
		"'; DROP TABLE users; --",
		"' OR '1'='1",
		"UNION SELECT password FROM users",
		"1; SELECT * FROM admin",

		// XSS injection
		"<script>alert(1)</script>",
		"javascript:alert(document.cookie)",
		"'><img src=x onerror=alert(1)>",
		"\"><script>alert(1)</script>",

		// Command injection
		"; rm -rf /",
		"| cat /etc/passwd",
		"$(whoami)",
		"`id`",
		"param && malicious",

		// Path traversal
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"....//....//....//etc//passwd",

		// LDAP injection
		"*)(uid=*))(|(uid=*",
		"admin)(|(password=*)",

		// NoSQL injection
		"'; return true; //",
		"{\"$gt\": \"\"}",
		"1'; return {injection: true}; //",

		// Template injection
		"{{7*7}}",
		"${7*7}",
		"<%= 7*7 %>",
		"{{config.items()}}",

		// CRLF injection
		"value\r\nContent-Length: 0\r\n\r\n",
		"param\nInjected: header",

		// Unicode attacks
		"válue",
		"vaĺue",       // Different Unicode characters
		"value\u202e", // Right-to-left override

		// Buffer overflow
		strings.Repeat("A", 10000),
		strings.Repeat("💀", 1000),

		// Null bytes
		"value\x00injected",
		"\x00\x00\x00",

		// Valid parameters
		"normal_value",
		"user@example.com",
		"123456",
		"valid-param_value",
		"",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, param string) {
		// Test parameter validation
		isValid := validateQueryParameter(param)
		_ = isValid

		// Test parameter sanitization
		sanitized := sanitizeQueryParameter(param)

		// Verify sanitization removes dangerous patterns
		if strings.Contains(sanitized, "\x00") {
			t.Error("Sanitized parameter contains null bytes")
		}

		if strings.Contains(sanitized, "\r") || strings.Contains(sanitized, "\n") {
			t.Error("Sanitized parameter contains line breaks")
		}

		// Test parameter encoding
		encoded := encodeQueryParameter(param)
		decoded, err := url.QueryUnescape(encoded)
		if err != nil {
			t.Error("Query parameter encoding/decoding failed")
		}
		_ = decoded

		// Test injection detection
		hasInjection := detectInjectionPatterns(param)
		_ = hasInjection

		// Test parameter length validation
		if len(param) > 0 {
			isValidLength := validateParameterLengthNetwork(param)
			_ = isValidLength
		}
	})
}

// FuzzNetworkConfiguration tests network configuration input validation
func FuzzNetworkConfiguration(f *testing.F) {
	seeds := []string{
		// IP address attacks
		"0.0.0.0",
		"shared.GetInternalHostname",
		"169.254.169.254", // AWS metadata
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.1",

		// IPv6 attacks
		"::1",
		"::ffff:shared.GetInternalHostname",
		"fe80::1",
		"2001:db8::1",

		// Port attacks
		"22", "23", "25", "53", "80", "135", "139", "443", "445", "993", "995",
		"3389", "5432", "3306", "1433", "6379", "27017",

		// CIDR attacks
		"0.0.0.0/0",
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",

		// DNS attacks
		"localhost",
		"metadata.google.internal",
		"169.254.169.254.xip.io",
		"shared.GetInternalHostname.nip.io",

		// Injection in network config
		"192.168.1.1; rm -rf /",
		"localhost | cat /etc/passwd",
		"$(whoami).example.com",

		// Unicode domains
		"еxample.com", // Cyrillic е
		"goog1е.com",
		"аpple.com",

		// Long values
		strings.Repeat("1", 1000) + ".com",
		strings.Repeat("A", 255) + ".local",

		// Valid configurations
		"example.com",
		"api.service.local",
		"203.0.113.1", // TEST-NET
		"80",
		"443",
		"",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, config string) {
		// Test IP address validation
		isValidIP := validateIPAddress(config)
		_ = isValidIP

		// Test hostname validation
		isValidHostname := validateNetworkHostname(config)
		_ = isValidHostname

		// Test port validation
		isValidPort := validatePort(config)
		_ = isValidPort

		// Test CIDR validation
		isValidCIDR := validateCIDR(config)
		_ = isValidCIDR

		// Test private network detection
		isPrivate := isPrivateNetworkAddress(config)
		_ = isPrivate

		// Test network config sanitization
		sanitized := sanitizeNetworkConfig(config)
		if !utf8.ValidString(sanitized) {
			t.Error("Sanitized network config is not valid UTF-8")
		}

		// Test DNS resolution safety
		isSafeDNS := isDNSResolutionSafe(config)
		_ = isSafeDNS
	})
}

// Helper functions that should be implemented

func validateURL(rawURL string) bool {
	// TODO: Implement URL validation
	_, err := url.Parse(rawURL)
	return err == nil && len(rawURL) < 2048
}

func parseURL(rawURL string) (*url.URL, error) {
	// TODO: Implement secure URL parsing
	return url.Parse(rawURL)
}

func validateHostname(hostname string) bool {
	// TODO: Implement hostname validation
	return len(hostname) > 0 && len(hostname) < 253 && !strings.Contains(hostname, "..")
}

func validateURLScheme(scheme string) bool {
	// TODO: Implement URL scheme validation
	allowed := []string{"http", "https"}
	for _, a := range allowed {
		if scheme == a {
			return true
		}
	}
	return false
}

func sanitizeURL(rawURL string) string {
	// TODO: Implement URL sanitization
	return strings.ReplaceAll(rawURL, "\x00", "")
}

func isSSRFSafeURL(rawURL string) bool {
	// TODO: Implement SSRF protection
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Block private networks
	privateHosts := []string{"localhost", "shared.GetInternalHostname", "169.254.169.254"}
	for _, host := range privateHosts {
		if strings.Contains(u.Host, host) {
			return false
		}
	}
	return true
}

func normalizeURL(rawURL string) string {
	// TODO: Implement URL normalization
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.String()
}

func validateHTTPHeader(value string) bool {
	// TODO: Implement HTTP header validation
	return !strings.Contains(value, "\r") && !strings.Contains(value, "\n") && len(value) < 8192
}

func sanitizeHTTPHeader(value string) string {
	// TODO: Implement HTTP header sanitization
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	value = strings.ReplaceAll(value, "\x00", "")
	if len(value) > 8192 {
		value = value[:8192]
	}
	return value
}

func encodeHTTPHeader(value string) string {
	// TODO: Implement HTTP header encoding
	return value
}

func isValidHTTPHeaderEncoding(encoded string) bool {
	// TODO: Implement header encoding validation
	return utf8.ValidString(encoded)
}

func validateQueryParameter(param string) bool {
	// TODO: Implement query parameter validation
	return len(param) < 4096 && !strings.Contains(param, "\x00")
}

func sanitizeQueryParameter(param string) string {
	// TODO: Implement query parameter sanitization
	param = strings.ReplaceAll(param, "\x00", "")
	param = strings.ReplaceAll(param, "\r", "")
	param = strings.ReplaceAll(param, "\n", "")
	return param
}

func encodeQueryParameter(param string) string {
	// TODO: Implement query parameter encoding
	return url.QueryEscape(param)
}

func detectInjectionPatterns(param string) bool {
	// TODO: Implement injection pattern detection
	patterns := []string{
		"'", "\"", "<script>", "javascript:", "'; DROP",
		"UNION SELECT", "$(", "`", "||", "&&",
	}
	for _, pattern := range patterns {
		if strings.Contains(strings.ToLower(param), strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func validateParameterLengthNetwork(param string) bool {
	// TODO: Implement parameter length validation
	return len(param) <= 4096
}

func validateIPAddress(ip string) bool {
	// TODO: Implement IP address validation
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	// Basic validation - should use net.ParseIP in real implementation
	return true
}

func validateNetworkHostname(hostname string) bool {
	// TODO: Implement network hostname validation
	return validateHostname(hostname)
}

func validatePort(port string) bool {
	// TODO: Implement port validation
	// Should parse as integer and check range 1-65535
	return len(port) > 0 && len(port) < 6
}

func validateCIDR(cidr string) bool {
	// TODO: Implement CIDR validation
	return strings.Contains(cidr, "/")
}

func isPrivateNetworkAddress(addr string) bool {
	// TODO: Implement private network detection
	privateRanges := []string{"127.", "10.", "192.168.", "172.16."}
	for _, private := range privateRanges {
		if strings.HasPrefix(addr, private) {
			return true
		}
	}
	return false
}

func sanitizeNetworkConfig(config string) string {
	// TODO: Implement network config sanitization
	return strings.ReplaceAll(config, "\x00", "")
}

func isDNSResolutionSafe(hostname string) bool {
	// TODO: Implement DNS resolution safety check
	return !isPrivateNetworkAddress(hostname)
}
