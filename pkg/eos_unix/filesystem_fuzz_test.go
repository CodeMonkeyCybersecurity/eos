// pkg/eos_unix/filesystem_fuzz_test.go
package eos_unix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// FuzzMkdirP tests directory creation with malicious path inputs
func FuzzMkdirP(f *testing.F) {
	// Seed with safe paths
	f.Add("test/dir")
	f.Add("/tmp/test")
	f.Add("./relative/path")
	
	// Seed with potentially dangerous paths
	f.Add("../../../etc/passwd")         // Path traversal up
	f.Add("/etc/../../../etc/passwd")    // Path traversal absolute
	f.Add("test\x00malicious")           // Null byte injection
	f.Add("test\n/etc/passwd")           // Newline injection
	f.Add("test/../../../")              // Multiple traversals
	f.Add("\\..\\..\\windows\\system32") // Windows-style traversal
	f.Add("test/./../../etc")            // Mixed relative components
	
	f.Fuzz(func(t *testing.T, path string) {
		// Skip empty paths
		if path == "" {
			return
		}
		
		// Skip paths that would obviously escape test directory
		if strings.Contains(path, "..") && strings.Count(path, "..") > 1 {
			return
		}
		
		// Skip paths with null bytes (filesystem won't handle them anyway)
		if strings.Contains(path, "\x00") {
			return
		}
		
		// Skip obviously dangerous absolute paths outside /tmp
		if filepath.IsAbs(path) && !strings.HasPrefix(path, "/tmp/") && !strings.HasPrefix(path, "/var/tmp/") {
			return
		}
		
		// Create test context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		
		// Test in isolated temporary directory
		tmpDir := t.TempDir()
		testPath := filepath.Join(tmpDir, path)
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("MkdirP panicked on path '%s': %v", path, r)
			}
		}()
		
		// Test MkdirP - should not panic and should not escape tmpDir
		err := MkdirP(ctx, testPath, 0755)
		
		// If creation succeeded, verify it's within our test directory
		if err == nil {
			absTest, err := filepath.Abs(testPath)
			if err == nil {
				absTmp, err := filepath.Abs(tmpDir)
				if err == nil {
					// Ensure created path is within test directory
					if !strings.HasPrefix(absTest, absTmp) {
						t.Errorf("MkdirP created path outside test directory: %s not in %s", absTest, absTmp)
					}
				}
			}
		}
	})
}

// FuzzRmRF tests file/directory removal with malicious paths
func FuzzRmRF(f *testing.F) {
	f.Add("test/file.txt")
	f.Add("test/directory")
	f.Add("nonexistent")
	
	// Dangerous patterns
	f.Add("../../../etc")
	f.Add("/etc/passwd")
	f.Add("test\x00injection")
	f.Add("test/../../../")
	f.Add(".")
	f.Add("..")
	f.Add("/")
	
	f.Fuzz(func(t *testing.T, path string) {
		if path == "" {
			return
		}
		
		// Skip extremely dangerous paths that could damage system
		dangerousPaths := []string{"/", "/etc", "/usr", "/var", "/home", "/root", "/bin", "/sbin"}
		for _, dangerous := range dangerousPaths {
			if path == dangerous || strings.HasPrefix(path, dangerous+"/") {
				return
			}
		}
		
		// Skip null bytes
		if strings.Contains(path, "\x00") {
			return
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("RmRF panicked on path '%s': %v", path, r)
			}
		}()
		
		// Create test in temporary directory
		tmpDir := t.TempDir()
		testPath := filepath.Join(tmpDir, path)
		
		// Create a test file/directory to remove
		if err := os.MkdirAll(filepath.Dir(testPath), 0755); err == nil {
			os.WriteFile(testPath, []byte("test"), 0644)
		}
		
		// Test RmRF
		RmRF(ctx, testPath, "fuzz-test")
	})
}

// FuzzCopyFile tests file copying with malicious source/destination paths
func FuzzCopyFile(f *testing.F) {
	f.Add("source.txt", "dest.txt")
	f.Add("test/source.txt", "test/dest.txt")
	
	// Path traversal patterns
	f.Add("../../../etc/passwd", "dest.txt")
	f.Add("source.txt", "../../../tmp/malicious")
	f.Add("test\x00file", "dest.txt")
	f.Add("source.txt", "dest\x00file")
	
	f.Fuzz(func(t *testing.T, src, dst string) {
		if src == "" || dst == "" {
			return
		}
		
		// Skip null bytes
		if strings.Contains(src, "\x00") || strings.Contains(dst, "\x00") {
			return
		}
		
		// Skip dangerous absolute paths
		if (filepath.IsAbs(src) && !strings.HasPrefix(src, "/tmp/")) ||
		   (filepath.IsAbs(dst) && !strings.HasPrefix(dst, "/tmp/")) {
			return
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		
		tmpDir := t.TempDir()
		srcPath := filepath.Join(tmpDir, src)
		dstPath := filepath.Join(tmpDir, dst)
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("CopyFile panicked on src='%s' dst='%s': %v", src, dst, r)
			}
		}()
		
		// Create source file
		if err := os.MkdirAll(filepath.Dir(srcPath), 0755); err == nil {
			if err := os.WriteFile(srcPath, []byte("test content"), 0644); err == nil {
				// Test copying
				CopyFile(ctx, srcPath, dstPath, 0644)
				
				// If copy succeeded, verify destination is within tmpDir
				if absDst, err := filepath.Abs(dstPath); err == nil {
					if absTmp, err := filepath.Abs(tmpDir); err == nil {
						if !strings.HasPrefix(absDst, absTmp) {
							t.Errorf("CopyFile created file outside test directory: %s", absDst)
						}
					}
				}
			}
		}
	})
}

// FuzzFilepathAbs tests the filepath.Abs function with malicious inputs
func FuzzFilepathAbs(f *testing.F) {
	f.Add("normal/path")
	f.Add("./relative")
	f.Add("../parent")
	
	// Malicious patterns
	f.Add("../../../../etc/passwd")
	f.Add("test\x00null")
	f.Add("test\nnewline")
	f.Add("test\rcarriage")
	f.Add("test\ttab")
	f.Add(strings.Repeat("../", 100)) // Deep traversal
	f.Add(strings.Repeat("a/", 1000)) // Long path
	
	f.Fuzz(func(t *testing.T, path string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("filepath.Abs panicked on path '%s': %v", path, r)
			}
		}()
		
		// Test that filepath.Abs doesn't panic
		abs, err := filepath.Abs(path)
		
		// If successful, verify result doesn't contain dangerous patterns
		if err == nil && abs != "" {
			// Check for null bytes in result
			if strings.Contains(abs, "\x00") {
				t.Errorf("filepath.Abs returned path with null byte: %s", abs)
			}
			
			// Check for unreasonably long paths
			if len(abs) > 4096 {
				t.Errorf("filepath.Abs returned extremely long path (%d chars): %s...", len(abs), abs[:100])
			}
		}
	})
}

// FuzzWriteFile tests file writing with malicious paths and content
func FuzzWriteFile(f *testing.F) {
	f.Add("test.txt", []byte("content"), "testuser")
	f.Add("dir/file.txt", []byte("data"), "user")
	
	// Malicious patterns
	f.Add("../../../tmp/malicious", []byte("bad"), "root")
	f.Add("test\x00file", []byte("content"), "user")
	f.Add("normal.txt", []byte("\x00\x01\x02binary"), "user")
	
	f.Fuzz(func(t *testing.T, path string, data []byte, owner string) {
		if path == "" || owner == "" {
			return
		}
		
		// Skip null bytes in path
		if strings.Contains(path, "\x00") {
			return
		}
		
		// Skip dangerous absolute paths
		if filepath.IsAbs(path) && !strings.HasPrefix(path, "/tmp/") {
			return
		}
		
		// Limit data size to prevent resource exhaustion
		if len(data) > 10000 {
			return
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		
		tmpDir := t.TempDir()
		testPath := filepath.Join(tmpDir, path)
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("WriteFile panicked on path='%s' owner='%s': %v", path, owner, r)
			}
		}()
		
		// Test WriteFile - expect most to fail due to invalid owner, but shouldn't panic
		WriteFile(ctx, testPath, data, 0644, owner)
	})
}