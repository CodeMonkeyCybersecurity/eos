package shared

import (
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzFilePathValidation tests file path validation for directory traversal attacks
func FuzzFilePathValidation(f *testing.F) {
	// Add seed corpus with path traversal attack vectors
	seeds := []string{
		// Basic directory traversal
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"....//....//....//etc//passwd",
		
		// URL encoded traversal
		"..%2f..%2f..%2fetc%2fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd",
		"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
		
		// Unicode traversal
		"..∕..∕..∕etc∕passwd",
		"..⁄..⁄..⁄etc⁄passwd",
		"..\u2215..\u2215..\u2215etc\u2215passwd",
		
		// Null byte injection
		"../../../etc/passwd\x00.txt",
		"safe.txt\x00../../../etc/passwd",
		
		// Long path attacks
		strings.Repeat("../", 1000) + "etc/passwd",
		strings.Repeat("A", 4096) + "/file.txt",
		
		// UNC path attacks (Windows)
		"\\\\server\\share\\file.txt",
		"\\\\?\\C:\\Windows\\System32\\file.txt",
		"\\\\?\\UNC\\server\\share\\file.txt",
		
		// Device file attacks (Unix)
		"/dev/null",
		"/dev/zero",
		"/dev/random",
		"/proc/self/environ",
		"/proc/version",
		
		// Symbolic link attacks
		"/tmp/symlink",
		"../symlink",
		"symlink/../../../etc/passwd",
		
		// Hidden files
		".htaccess",
		".env",
		".git/config",
		".ssh/id_rsa",
		
		// Valid paths (should pass)
		"file.txt",
		"subdir/file.txt",
		"/absolute/path/file.txt",
		"./relative/file.txt",
		"",
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, path string) {
		// Test path validation
		isValid := validateFilePath(path)
		_ = isValid
		
		// Test path sanitization
		sanitized := sanitizeFilePath(path)
		
		// Verify sanitization removes dangerous elements
		if strings.Contains(sanitized, "..") && isValid {
			t.Error("Sanitized path contains directory traversal but was marked valid")
		}
		
		if strings.Contains(sanitized, "\x00") {
			t.Error("Sanitized path contains null bytes")
		}
		
		// Test path normalization
		normalized := normalizeFilePath(path)
		if !utf8.ValidString(normalized) {
			t.Error("Normalized path is not valid UTF-8")
		}
		
		// Test secure path joining
		securePath := secureJoinPath("/base", path)
		if !strings.HasPrefix(securePath, "/base") && len(path) > 0 {
			t.Error("Secure path join allowed escape from base directory")
		}
		
		// Test file extension validation
		ext := filepath.Ext(path)
		isAllowedExt := validateFileExtension(ext)
		_ = isAllowedExt
	})
}

// FuzzFileNameValidation tests filename validation for injection attacks
func FuzzFileNameValidation(f *testing.F) {
	seeds := []string{
		// Command injection in filenames
		"file.txt; rm -rf /",
		"file.txt | cat /etc/passwd",
		"file.txt && malicious",
		"$(whoami).txt",
		"`id`.txt",
		
		// Script injection
		"<script>alert(1)</script>.txt",
		"file.php.txt",
		"file.jsp.txt",
		"file.asp.txt",
		
		// Reserved Windows names
		"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "LPT1", "LPT2",
		"con.txt", "prn.log",
		
		// Special characters
		"file:name.txt",
		"file*name.txt",
		"file?name.txt",
		"file\"name.txt",
		"file<name.txt",
		"file>name.txt",
		"file|name.txt",
		
		// Unicode filename attacks
		"файл.txt", // Cyrillic
		"文件.txt", // Chinese
		"file\u202e.txt", // Right-to-left override
		"file\ufeff.txt", // BOM
		
		// Long filenames
		strings.Repeat("A", 255) + ".txt",
		strings.Repeat("A", 1000) + ".txt",
		
		// Hidden files
		".htaccess",
		"..hidden",
		"...hidden",
		
		// Valid filenames
		"file.txt",
		"document.pdf",
		"image.jpg",
		"data.json",
		"",
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, filename string) {
		// Test filename validation
		isValid := validateFileName(filename)
		_ = isValid
		
		// Test filename sanitization
		sanitized := sanitizeFileName(filename)
		
		// Verify sanitization removes dangerous characters
		dangerousChars := []string{"<", ">", ":", "\"", "|", "?", "*", "\x00"}
		for _, char := range dangerousChars {
			if strings.Contains(sanitized, char) {
				t.Errorf("Sanitized filename contains dangerous character: %s", char)
			}
		}
		
		// Test filename length validation
		if len(sanitized) > 255 {
			t.Error("Sanitized filename exceeds maximum length")
		}
		
		// Test reserved name detection
		isReserved := isReservedFileName(filename)
		_ = isReserved
		
		// Test safe filename generation
		safeFilename := generateSafeFileName(filename)
		if !isValidSafeFileName(safeFilename) {
			t.Error("Generated safe filename is not valid")
		}
	})
}

// FuzzFileContentValidation tests file content validation for malicious content
func FuzzFileContentValidation(f *testing.F) {
	seeds := []string{
		// Script content
		"#!/bin/bash\nrm -rf /",
		"<?php system($_GET['cmd']); ?>",
		"<script>alert('xss')</script>",
		"javascript:alert(1)",
		
		// Binary content
		"\x7fELF", // ELF header
		"MZ", // PE header
		"\x89PNG", // PNG header
		"PK", // ZIP header
		
		// Command injection in content
		"data; $(malicious)",
		"data | cat /etc/passwd",
		"data && rm -rf /",
		
		// SQL injection patterns
		"'; DROP TABLE users; --",
		"' OR '1'='1",
		"UNION SELECT password FROM users",
		
		// XSS patterns
		"<img src=x onerror=alert(1)>",
		"javascript:alert(document.cookie)",
		"data:text/html,<script>alert(1)</script>",
		
		// Path injection in content
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		
		// Large content (DoS)
		strings.Repeat("A", 10000),
		strings.Repeat("💀", 1000), // Unicode bomb
		
		// Null bytes
		"data\x00malicious",
		"\x00\x00\x00\x00",
		
		// Valid content
		"Hello, world!",
		"This is normal text content.",
		"JSON: {\"key\": \"value\"}",
		"",
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, content string) {
		// Test content validation
		isValid := validateFileContent(content)
		_ = isValid
		
		// Test content sanitization
		sanitized := sanitizeFileContent(content)
		
		// Verify sanitization removes dangerous patterns
		if strings.Contains(sanitized, "\x00") {
			t.Error("Sanitized content contains null bytes")
		}
		
		// Test content type detection
		contentType := detectContentType(content)
		if !isAllowedContentType(contentType) && isValid {
			t.Error("Content marked as valid but has disallowed content type")
		}
		
		// Test size validation
		if len(content) > 0 {
			isValidSize := validateContentSize(len(content))
			_ = isValidSize
		}
		
		// Test encoding validation
		if !utf8.ValidString(content) {
			// Binary content should be handled differently
			isBinary := isBinaryContent(content)
			_ = isBinary
		}
	})
}

// FuzzFileUpload tests file upload validation
func FuzzFileUpload(f *testing.F) {
	seeds := []string{
		// Malicious file extensions
		"malware.exe",
		"script.bat",
		"payload.sh",
		"virus.scr",
		"trojan.pif",
		
		// Double extensions
		"image.jpg.exe",
		"document.pdf.bat",
		"archive.zip.sh",
		
		// Null byte attacks
		"image.jpg\x00.exe",
		"safe.txt\x00malicious.sh",
		
		// MIME type spoofing
		"script.exe", // Would need MIME validation
		"image.php",
		"document.jsp",
		
		// Archive attacks
		"../../exploit.zip",
		"zipbomb.zip",
		
		// Valid uploads
		"image.jpg",
		"document.pdf",
		"archive.zip",
		"text.txt",
	}
	
	for _, seed := range seeds {
		f.Add(seed)
	}
	
	f.Fuzz(func(t *testing.T, filename string) {
		// Test upload validation
		isValidUpload := validateFileUpload(filename)
		_ = isValidUpload
		
		// Test extension whitelist
		ext := strings.ToLower(filepath.Ext(filename))
		isAllowedExt := isAllowedUploadExtension(ext)
		_ = isAllowedExt
		
		// Test filename in upload context
		uploadPath := generateUploadPath(filename)
		if !isSecureUploadPath(uploadPath) {
			t.Error("Generated upload path is not secure")
		}
		
		// Test quarantine filename generation
		quarantineName := generateQuarantineName(filename)
		if !isValidQuarantineName(quarantineName) {
			t.Error("Generated quarantine name is not valid")
		}
	})
}

// Helper functions that should be implemented in the actual file operations package

func validateFilePath(path string) bool {
	// TODO: Implement comprehensive file path validation
	return !strings.Contains(path, "..") && !strings.Contains(path, "\x00")
}

func sanitizeFilePath(path string) string {
	// TODO: Implement file path sanitization
	path = strings.ReplaceAll(path, "\x00", "")
	path = filepath.Clean(path)
	return path
}

func normalizeFilePath(path string) string {
	// TODO: Implement file path normalization
	return filepath.Clean(path)
}

func secureJoinPath(base, path string) string {
	// TODO: Implement secure path joining that prevents directory traversal
	joined := filepath.Join(base, path)
	if !strings.HasPrefix(joined, base) {
		return base // Prevent escape
	}
	return joined
}

func validateFileExtension(ext string) bool {
	// TODO: Implement file extension validation
	allowedExts := []string{".txt", ".jpg", ".png", ".pdf", ".zip"}
	for _, allowed := range allowedExts {
		if strings.ToLower(ext) == allowed {
			return true
		}
	}
	return false
}

func validateFileName(filename string) bool {
	// TODO: Implement filename validation
	if len(filename) == 0 || len(filename) > 255 {
		return false
	}
	
	// Check for dangerous characters
	dangerousChars := []string{"<", ">", ":", "\"", "|", "?", "*", "\x00"}
	for _, char := range dangerousChars {
		if strings.Contains(filename, char) {
			return false
		}
	}
	
	return true
}

func sanitizeFileName(filename string) string {
	// TODO: Implement filename sanitization
	dangerousChars := map[string]string{
		"<": "", ">": "", ":": "", "\"": "", "|": "",
		"?": "", "*": "", "\x00": "", "/": "_", "\\": "_",
	}
	
	for old, new := range dangerousChars {
		filename = strings.ReplaceAll(filename, old, new)
	}
	
	// Limit length
	if len(filename) > 255 {
		filename = filename[:255]
	}
	
	return filename
}

func isReservedFileName(filename string) bool {
	// TODO: Implement reserved filename detection
	reserved := []string{"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "LPT1", "LPT2"}
	upper := strings.ToUpper(filename)
	for _, res := range reserved {
		if upper == res || strings.HasPrefix(upper, res+".") {
			return true
		}
	}
	return false
}

func generateSafeFileName(filename string) string {
	// TODO: Implement safe filename generation
	return sanitizeFileName(filename)
}

func isValidSafeFileName(filename string) bool {
	// TODO: Implement safe filename validation
	return validateFileName(filename) && !isReservedFileName(filename)
}

func validateFileContent(content string) bool {
	// TODO: Implement file content validation
	return !strings.Contains(content, "\x00") && len(content) < 1000000
}

func sanitizeFileContent(content string) string {
	// TODO: Implement file content sanitization
	return strings.ReplaceAll(content, "\x00", "")
}

func detectContentType(content string) string {
	// TODO: Implement content type detection
	if strings.HasPrefix(content, "#!/") {
		return "script"
	}
	if strings.Contains(content, "<?php") {
		return "php"
	}
	return "text"
}

func isAllowedContentType(contentType string) bool {
	// TODO: Implement content type allowlist
	allowed := []string{"text", "json", "xml"}
	for _, a := range allowed {
		if contentType == a {
			return true
		}
	}
	return false
}

func validateContentSize(size int) bool {
	// TODO: Implement content size validation
	return size > 0 && size < 10000000 // 10MB limit
}

func isBinaryContent(content string) bool {
	// TODO: Implement binary content detection
	return !utf8.ValidString(content)
}

func validateFileUpload(filename string) bool {
	// TODO: Implement upload validation
	return validateFileName(filename) && validateFileExtension(filepath.Ext(filename))
}

func isAllowedUploadExtension(ext string) bool {
	// TODO: Implement upload extension allowlist
	allowed := []string{".jpg", ".png", ".gif", ".pdf", ".txt", ".zip"}
	for _, a := range allowed {
		if ext == a {
			return true
		}
	}
	return false
}

func generateUploadPath(filename string) string {
	// TODO: Implement secure upload path generation
	safe := sanitizeFileName(filename)
	return "/uploads/" + safe
}

func isSecureUploadPath(path string) bool {
	// TODO: Implement upload path security validation
	return strings.HasPrefix(path, "/uploads/") && !strings.Contains(path, "..")
}

func generateQuarantineName(filename string) string {
	// TODO: Implement quarantine name generation
	return "quarantine_" + sanitizeFileName(filename)
}

func isValidQuarantineName(name string) bool {
	// TODO: Implement quarantine name validation
	return strings.HasPrefix(name, "quarantine_") && validateFileName(name)
}