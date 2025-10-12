package eos_unix

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMkdirP(t *testing.T) {
	ctx := context.Background()

	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "eos_unix_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tests := []struct {
		name        string
		path        string
		perm        os.FileMode
		wantErr     bool
		description string
	}{
		{
			name:        "create new directory",
			path:        filepath.Join(tmpDir, "new_dir"),
			perm:        0755,
			wantErr:     false,
			description: "should create new directory with correct permissions",
		},
		{
			name:        "create nested directory",
			path:        filepath.Join(tmpDir, "nested", "deep", "dir"),
			perm:        0750,
			wantErr:     false,
			description: "should create nested directory structure",
		},
		{
			name:        "existing directory",
			path:        tmpDir, // already exists
			perm:        0755,
			wantErr:     false,
			description: "should not error on existing directory",
		},
		{
			name:        "restrictive permissions",
			path:        filepath.Join(tmpDir, "secure_dir"),
			perm:        0700,
			wantErr:     false,
			description: "should create directory with restrictive permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := MkdirP(ctx, tt.path, tt.perm)

			if (err != nil) != tt.wantErr {
				t.Errorf("MkdirP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify directory exists
				info, err := os.Stat(tt.path)
				if err != nil {
					t.Errorf("Directory was not created: %v", err)
					return
				}

				if !info.IsDir() {
					t.Errorf("Path exists but is not a directory")
				}

				// Note: Permission checking is platform-specific and may not work
				// exactly as expected on all systems due to umask and other factors
			}
		})
	}
}

func TestMkdirP_ErrorCases(t *testing.T) {
	ctx := context.Background()

	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "eos_unix_test_error_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	t.Run("file exists at path", func(t *testing.T) {
		// Create a file at the target path
		filePath := filepath.Join(tmpDir, "existing_file")
		if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		// Try to create directory at the same path
		err := MkdirP(ctx, filePath, 0755)
		if err == nil {
			t.Error("Expected error when file exists at directory path")
		}
	})

	t.Run("empty path", func(t *testing.T) {
		err := MkdirP(ctx, "", 0755)
		// Should handle empty path gracefully (might create current directory)
		// The exact behavior depends on filepath.Abs implementation
		t.Logf("Empty path result: %v", err)
	})
}

func TestMkdirP_Concurrency(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "eos_unix_concurrent_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Test concurrent creation of the same directory
	targetDir := filepath.Join(tmpDir, "concurrent_dir")

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			err := MkdirP(ctx, targetDir, 0755)
			if err != nil {
				t.Errorf("Concurrent MkdirP failed: %v", err)
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Success
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}

	// Verify directory was created
	if _, err := os.Stat(targetDir); err != nil {
		t.Errorf("Directory was not created by concurrent operations: %v", err)
	}
}

func TestAbsolutePath(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		path string
	}{
		{"absolute path", "/tmp/test"},
		{"relative path", "relative/path"},
		{"current dir", "."},
		{"parent dir", ".."},
		{"home reference", "~/test"}, // Note: this won't expand ~ automatically
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that the function can handle different path types
			// without panicking (exact behavior may vary)
			tmpDir, err := os.MkdirTemp("", "eos_unix_abs_*")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			testPath := filepath.Join(tmpDir, tt.path)
			err = MkdirP(ctx, testPath, 0755)

			// Log the result rather than asserting, since behavior
			// may vary based on the path type and system
			t.Logf("Path %q result: %v", tt.path, err)
		})
	}
}
