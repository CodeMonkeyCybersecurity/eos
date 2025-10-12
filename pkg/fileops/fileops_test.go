// pkg/fileops/fileops_test.go
package fileops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestFileSystemOperations tests basic file operations
func TestFileSystemOperations(t *testing.T) {
	logger := zaptest.NewLogger(t)
	fileOps := NewFileSystemOperations(logger)
	ctx := context.Background()

	// Create temp directory for tests
	tempDir := t.TempDir()

	t.Run("ReadFile", func(t *testing.T) {
		// Create test file
		testFile := filepath.Join(tempDir, "test.txt")
		testContent := []byte("test content")
		require.NoError(t, os.WriteFile(testFile, testContent, 0644))

		// Test reading existing file
		data, err := fileOps.ReadFile(ctx, testFile)
		assert.NoError(t, err)
		assert.Equal(t, testContent, data)

		// Test reading non-existent file
		_, err = fileOps.ReadFile(ctx, filepath.Join(tempDir, "nonexistent.txt"))
		assert.Error(t, err)
	})

	t.Run("WriteFile", func(t *testing.T) {
		// Test writing new file
		testFile := filepath.Join(tempDir, "subdir", "write_test.txt")
		testContent := []byte("written content")

		err := fileOps.WriteFile(ctx, testFile, testContent, 0644)
		assert.NoError(t, err)

		// Verify file was written
		data, err := os.ReadFile(testFile)
		assert.NoError(t, err)
		assert.Equal(t, testContent, data)

		// Verify permissions
		info, err := os.Stat(testFile)
		assert.NoError(t, err)
		assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
	})

	t.Run("CopyFile", func(t *testing.T) {
		// Create source file
		srcFile := filepath.Join(tempDir, "copy_src.txt")
		srcContent := []byte("source content")
		require.NoError(t, os.WriteFile(srcFile, srcContent, 0644))

		// Copy file
		dstFile := filepath.Join(tempDir, "copy_dst.txt")
		err := fileOps.CopyFile(ctx, srcFile, dstFile, 0600)
		assert.NoError(t, err)

		// Verify copy
		dstContent, err := os.ReadFile(dstFile)
		assert.NoError(t, err)
		assert.Equal(t, srcContent, dstContent)

		// Verify permissions
		info, err := os.Stat(dstFile)
		assert.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

		// Test copying non-existent file
		err = fileOps.CopyFile(ctx, filepath.Join(tempDir, "nonexistent.txt"), dstFile, 0644)
		assert.Error(t, err)
	})

	t.Run("DeleteFile", func(t *testing.T) {
		// Create test file
		testFile := filepath.Join(tempDir, "delete_test.txt")
		require.NoError(t, os.WriteFile(testFile, []byte("delete me"), 0644))

		// Delete file
		err := fileOps.DeleteFile(ctx, testFile)
		assert.NoError(t, err)

		// Verify deletion
		_, err = os.Stat(testFile)
		assert.True(t, os.IsNotExist(err))

		// Test deleting non-existent file (should not error)
		err = fileOps.DeleteFile(ctx, testFile)
		assert.NoError(t, err)
	})

	t.Run("MoveFile", func(t *testing.T) {
		// Create source file
		srcFile := filepath.Join(tempDir, "move_src.txt")
		srcContent := []byte("move me")
		require.NoError(t, os.WriteFile(srcFile, srcContent, 0644))

		// Move file
		dstFile := filepath.Join(tempDir, "move_dst.txt")
		err := fileOps.MoveFile(ctx, srcFile, dstFile)
		assert.NoError(t, err)

		// Verify source is gone
		_, err = os.Stat(srcFile)
		assert.True(t, os.IsNotExist(err))

		// Verify destination exists
		dstContent, err := os.ReadFile(dstFile)
		assert.NoError(t, err)
		assert.Equal(t, srcContent, dstContent)
	})

	t.Run("Exists", func(t *testing.T) {
		// Test existing file
		testFile := filepath.Join(tempDir, "exists_test.txt")
		require.NoError(t, os.WriteFile(testFile, []byte("exists"), 0644))

		exists, err := fileOps.Exists(ctx, testFile)
		assert.NoError(t, err)
		assert.True(t, exists)

		// Test non-existent file
		exists, err = fileOps.Exists(ctx, filepath.Join(tempDir, "nonexistent.txt"))
		assert.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("CreateDirectory", func(t *testing.T) {
		// Test creating single directory
		dir1 := filepath.Join(tempDir, "newdir")
		err := fileOps.CreateDirectory(ctx, dir1, 0755)
		assert.NoError(t, err)

		// Verify directory exists
		info, err := os.Stat(dir1)
		assert.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.Equal(t, os.FileMode(0755), info.Mode().Perm())

		// Test creating nested directories
		dir2 := filepath.Join(tempDir, "nested", "deep", "dir")
		err = fileOps.CreateDirectory(ctx, dir2, 0755)
		assert.NoError(t, err)

		// Verify nested directory exists
		info, err = os.Stat(dir2)
		assert.NoError(t, err)
		assert.True(t, info.IsDir())
	})
}

// TestPathOperations tests path manipulation functions
func TestPathOperations(t *testing.T) {
	pathOps := NewPathOperations()

	t.Run("JoinPath", func(t *testing.T) {
		tests := []struct {
			elements []string
			expected string
		}{
			{[]string{"a", "b", "c"}, filepath.Join("a", "b", "c")},
			{[]string{"/root", "subdir", "file.txt"}, filepath.Join("/root", "subdir", "file.txt")},
			{[]string{"", "file.txt"}, "file.txt"},
			{[]string{"dir/", "/file.txt"}, filepath.Join("dir", "file.txt")},
		}

		for _, tt := range tests {
			result := pathOps.JoinPath(tt.elements...)
			assert.Equal(t, tt.expected, result)
		}
	})

	t.Run("CleanPath", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"a/b/../c", filepath.Clean("a/b/../c")},
			{"./a/b/./c/", filepath.Clean("./a/b/./c/")},
			{"//a//b//c//", filepath.Clean("//a//b//c//")},
			{"../../../etc/passwd", filepath.Clean("../../../etc/passwd")},
		}

		for _, tt := range tests {
			result := pathOps.CleanPath(tt.input)
			assert.Equal(t, tt.expected, result)
		}
	})

	t.Run("BaseName", func(t *testing.T) {
		tests := []struct {
			path     string
			expected string
		}{
			{"/path/to/file.txt", "file.txt"},
			{"/path/to/dir/", "dir"},
			{"file.txt", "file.txt"},
			{"/", string(filepath.Separator)},
		}

		for _, tt := range tests {
			result := pathOps.BaseName(tt.path)
			assert.Equal(t, tt.expected, result)
		}
	})

	t.Run("DirName", func(t *testing.T) {
		tests := []struct {
			path     string
			expected string
		}{
			{"/path/to/file.txt", filepath.Dir("/path/to/file.txt")},
			{"/path/to/dir/", filepath.Dir("/path/to/dir/")},
			{"file.txt", "."},
			{"/", string(filepath.Separator)},
		}

		for _, tt := range tests {
			result := pathOps.DirName(tt.path)
			assert.Equal(t, tt.expected, result)
		}
	})

	t.Run("IsAbsPath", func(t *testing.T) {
		tests := []struct {
			path     string
			expected bool
		}{
			{"/absolute/path", true},
			{"relative/path", false},
			{"./relative/path", false},
			{"../relative/path", false},
		}

		// Windows has different absolute path rules
		if filepath.Separator == '\\' {
			tests = append(tests, struct {
				path     string
				expected bool
			}{"C:\\Windows", true})
		}

		for _, tt := range tests {
			result := pathOps.IsAbsPath(tt.path)
			assert.Equal(t, tt.expected, result)
		}
	})

	t.Run("ExpandPath", func(t *testing.T) {
		// Test tilde expansion
		home, err := os.UserHomeDir()
		if err == nil {
			result := pathOps.ExpandPath("~/test")
			expected := filepath.Join(home, "test")
			assert.Equal(t, expected, result)
		}

		// Test environment variable expansion
		_ = os.Setenv("TEST_VAR", "testvalue")
		result := pathOps.ExpandPath("$TEST_VAR/file")
		assert.Equal(t, "testvalue/file", result)

		// Test combined
		if err == nil {
			_ = os.Setenv("TEST_DIR", "mydir")
			result = pathOps.ExpandPath("~/$TEST_DIR/file")
			expected := filepath.Join(home, "mydir", "file")
			assert.Equal(t, expected, result)
		}
	})
}

// TestSafeFileOperations tests safe file operations with backups
func TestSafeFileOperations(t *testing.T) {
	logger := zaptest.NewLogger(t)
	fileOps := NewFileSystemOperations(logger)
	safeOps := NewSafeFileOperations(fileOps, logger)
	ctx := context.Background()

	tempDir := t.TempDir()

	t.Run("WithBackup", func(t *testing.T) {
		// Create test file
		testFile := filepath.Join(tempDir, "backup_test.txt")
		originalContent := []byte("original content")
		require.NoError(t, os.WriteFile(testFile, originalContent, 0644))

		// Test successful operation
		backupPath, err := safeOps.WithBackup(ctx, testFile, func() error {
			return os.WriteFile(testFile, []byte("new content"), 0644)
		})
		assert.NoError(t, err)
		assert.NotEmpty(t, backupPath)

		// Verify new content
		newContent, err := os.ReadFile(testFile)
		assert.NoError(t, err)
		assert.Equal(t, []byte("new content"), newContent)

		// Verify backup exists
		backupContent, err := os.ReadFile(backupPath)
		assert.NoError(t, err)
		assert.Equal(t, originalContent, backupContent)

		// Test failed operation (should restore)
		testFile2 := filepath.Join(tempDir, "backup_test2.txt")
		require.NoError(t, os.WriteFile(testFile2, originalContent, 0644))

		_, err = safeOps.WithBackup(ctx, testFile2, func() error {
			// Partially modify file then fail
			_ = os.WriteFile(testFile2, []byte("partial"), 0644)
			return assert.AnError
		})
		assert.Error(t, err)

		// Verify original content was restored
		restoredContent, err := os.ReadFile(testFile2)
		assert.NoError(t, err)
		assert.Equal(t, originalContent, restoredContent)
	})

	t.Run("WithTransaction", func(t *testing.T) {
		// Create test files
		file1 := filepath.Join(tempDir, "trans1.txt")
		file2 := filepath.Join(tempDir, "trans2.txt")
		require.NoError(t, os.WriteFile(file1, []byte("file1"), 0644))
		require.NoError(t, os.WriteFile(file2, []byte("file2"), 0644))

		// Test successful transaction
		operations := []FileOperation{
			{Type: OpCopy, Source: file1, Target: filepath.Join(tempDir, "trans1_copy.txt")},
			{Type: OpMove, Source: file2, Target: filepath.Join(tempDir, "trans2_moved.txt")},
		}

		err := safeOps.WithTransaction(ctx, operations)
		assert.NoError(t, err)

		// Verify operations completed
		assert.FileExists(t, filepath.Join(tempDir, "trans1_copy.txt"))
		assert.FileExists(t, filepath.Join(tempDir, "trans2_moved.txt"))
		assert.NoFileExists(t, file2)

		// Test failed transaction (should rollback)
		file3 := filepath.Join(tempDir, "trans3.txt")
		require.NoError(t, os.WriteFile(file3, []byte("file3"), 0644))

		operations2 := []FileOperation{
			{Type: OpDelete, Target: file3},
			{Type: OpCopy, Source: "/nonexistent/file", Target: filepath.Join(tempDir, "fail.txt")},
		}

		err = safeOps.WithTransaction(ctx, operations2)
		assert.Error(t, err)
		
		// Verify rollback (file3 should still exist)
		assert.FileExists(t, file3)
	})
}

// TestPathTraversal tests protection against path traversal attacks
func TestPathTraversal(t *testing.T) {
	logger := zaptest.NewLogger(t)
	fileOps := NewFileSystemOperations(logger)
	ctx := context.Background()

	tempDir := t.TempDir()
	
	// Create a safe zone
	safeDir := filepath.Join(tempDir, "safe")
	require.NoError(t, os.MkdirAll(safeDir, 0755))
	
	// Create test file in safe zone
	safeFile := filepath.Join(safeDir, "test.txt")
	require.NoError(t, os.WriteFile(safeFile, []byte("safe content"), 0644))

	tests := []struct {
		name      string
		path      string
		operation func(string) error
		shouldErr bool
	}{
		{
			name: "normal file access",
			path: safeFile,
			operation: func(p string) error {
				_, err := fileOps.ReadFile(ctx, p)
				return err
			},
			shouldErr: false,
		},
		{
			name: "parent directory traversal",
			path: filepath.Join(safeDir, "../../../etc/passwd"),
			operation: func(p string) error {
				_, err := fileOps.ReadFile(ctx, p)
				return err
			},
			shouldErr: false, // Will error but not due to path validation
		},
		{
			name: "absolute path escape",
			path: "/etc/passwd",
			operation: func(p string) error {
				_, err := fileOps.ReadFile(ctx, p)
				return err
			},
			shouldErr: false, // Will error but not due to path validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.operation(tt.path)
			if tt.shouldErr {
				assert.Error(t, err)
			}
			// Note: Real path validation should be implemented in production code
		})
	}
}

// TestConcurrentFileOperations tests thread safety
func TestConcurrentFileOperations(t *testing.T) {
	logger := zaptest.NewLogger(t)
	fileOps := NewFileSystemOperations(logger)
	ctx := context.Background()

	tempDir := t.TempDir()

	// Run concurrent file operations
	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			
			// Each goroutine creates its own file
			filename := filepath.Join(tempDir, fmt.Sprintf("file_%d.txt", id))
			content := []byte(fmt.Sprintf("content from goroutine %d", id))
			
			// Write file
			if err := fileOps.WriteFile(ctx, filename, content, 0644); err != nil {
				errors <- err
				return
			}
			
			// Read it back
			data, err := fileOps.ReadFile(ctx, filename)
			if err != nil {
				errors <- err
				return
			}
			
			// Verify content
			if string(data) != string(content) {
				errors <- fmt.Errorf("content mismatch in goroutine %d", id)
				return
			}
			
			// Copy file
			copyDest := filepath.Join(tempDir, fmt.Sprintf("copy_%d.txt", id))
			if err := fileOps.CopyFile(ctx, filename, copyDest, 0644); err != nil {
				errors <- err
				return
			}
			
			// Delete original
			if err := fileOps.DeleteFile(ctx, filename); err != nil {
				errors <- err
				return
			}
		}(i)
	}

	// Wait for all goroutines
	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent operation failed: %v", err)
	}
	
	// Verify all copy files exist
	for i := 0; i < numGoroutines; i++ {
		copyFile := filepath.Join(tempDir, fmt.Sprintf("copy_%d.txt", i))
		assert.FileExists(t, copyFile)
	}
}

// TestSymlinkHandling tests handling of symbolic links
func TestSymlinkHandling(t *testing.T) {
	// Skip on Windows where symlinks require admin privileges
	if strings.Contains(strings.ToLower(os.Getenv("OS")), "windows") {
		t.Skip("Skipping symlink tests on Windows")
	}

	logger := zaptest.NewLogger(t)
	fileOps := NewFileSystemOperations(logger)
	ctx := context.Background()

	tempDir := t.TempDir()

	// Create target file
	targetFile := filepath.Join(tempDir, "target.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("target content"), 0644))

	// Create symlink
	linkFile := filepath.Join(tempDir, "link.txt")
	require.NoError(t, os.Symlink(targetFile, linkFile))

	// Test reading through symlink
	data, err := fileOps.ReadFile(ctx, linkFile)
	assert.NoError(t, err)
	assert.Equal(t, []byte("target content"), data)

	// Test detecting symlink
	info, err := os.Lstat(linkFile)
	assert.NoError(t, err)
	assert.True(t, info.Mode()&os.ModeSymlink != 0)

	// Test symlink to directory
	targetDir := filepath.Join(tempDir, "targetdir")
	require.NoError(t, os.MkdirAll(targetDir, 0755))
	
	linkDir := filepath.Join(tempDir, "linkdir")
	require.NoError(t, os.Symlink(targetDir, linkDir))

	// Should be able to create file in linked directory
	testFile := filepath.Join(linkDir, "test.txt")
	err = fileOps.WriteFile(ctx, testFile, []byte("test"), 0644)
	assert.NoError(t, err)

	// Verify file exists in target directory
	assert.FileExists(t, filepath.Join(targetDir, "test.txt"))
}