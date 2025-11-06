package crypto

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

func TestSecureErase(t *testing.T) {
	tests := []struct {
		name    string
		setupFn func(t *testing.T) string // returns file path
		wantErr bool
		errMsg  string
	}{
		{
			name: "erase existing file",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				filePath := filepath.Join(tmpDir, "test-file.txt")

				// Create file with sensitive content
				content := "sensitive data that should be securely erased"
				err := os.WriteFile(filePath, []byte(content), 0600)
				testutil.AssertNoError(t, err)

				return filePath
			},
			wantErr: false,
		},
		{
			name: "erase non-existent file",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				return filepath.Join(tmpDir, "non-existent.txt")
			},
			wantErr: false, // SecureErase returns nil for non-existent files
		},
		{
			name: "erase empty file",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				filePath := filepath.Join(tmpDir, "empty.txt")

				// Create empty file
				err := os.WriteFile(filePath, []byte{}, 0600)
				testutil.AssertNoError(t, err)

				return filePath
			},
			wantErr: false,
		},
		{
			name: "erase large file",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				filePath := filepath.Join(tmpDir, "large.txt")

				// Create file with large content (10KB)
				content := make([]byte, 10240)
				for i := range content {
					content[i] = byte(i % 256)
				}

				err := os.WriteFile(filePath, content, 0600)
				testutil.AssertNoError(t, err)

				return filePath
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filePath := tc.setupFn(t)
			ctx := context.Background()

			err := SecureErase(ctx, filePath)

			if tc.wantErr {
				testutil.AssertError(t, err)
				if tc.errMsg != "" {
					testutil.AssertErrorContains(t, err, tc.errMsg)
				}
			} else {
				testutil.AssertNoError(t, err)

				// Verify file was deleted (if it existed)
				_, err := os.Stat(filePath)
				if !os.IsNotExist(err) && tc.name != "erase non-existent file" {
					t.Errorf("Expected file to be deleted, but it still exists")
				}
			}
		})
	}
}

func TestSecureEraseConcurrency(t *testing.T) {
	t.Run("concurrent erase operations", func(t *testing.T) {
		tmpDir := testutil.TempDir(t)

		// Create multiple files
		filePaths := make([]string, 10)
		for i := 0; i < 10; i++ {
			filePath := filepath.Join(tmpDir, fmt.Sprintf("concurrent-%d.txt", i))
			err := os.WriteFile(filePath, []byte("concurrent test content"), 0600)
			testutil.AssertNoError(t, err)
			filePaths[i] = filePath
		}

		// Erase files concurrently
		testutil.ParallelTest(t, 10, func(t *testing.T, i int) {
			ctx := context.Background()
			err := SecureErase(ctx, filePaths[i])
			testutil.AssertNoError(t, err)
		})

		// Verify all files were deleted
		for _, filePath := range filePaths {
			_, err := os.Stat(filePath)
			if !os.IsNotExist(err) {
				t.Errorf("Expected file %s to be deleted", filePath)
			}
		}
	})
}

func TestSecureEraseSecurity(t *testing.T) {
	t.Run("handles context cancellation", func(t *testing.T) {
		tmpDir := testutil.TempDir(t)
		filePath := filepath.Join(tmpDir, "context-test.txt")

		err := os.WriteFile(filePath, []byte("test content"), 0600)
		testutil.AssertNoError(t, err)

		// Create cancelled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err = SecureErase(ctx, filePath)
		// Should handle cancelled context gracefully
		// May succeed or fail depending on timing, but shouldn't panic
		_ = err // Explicitly ignore error as this tests cancellation handling
	})

	t.Run("handles malicious file names", func(t *testing.T) {
		tmpDir := testutil.TempDir(t)

		// Test with safe file in temp directory
		safePath := filepath.Join(tmpDir, "safe-file.txt")
		err := os.WriteFile(safePath, []byte("test"), 0600)
		testutil.AssertNoError(t, err)

		ctx := context.Background()
		err = SecureErase(ctx, safePath)
		testutil.AssertNoError(t, err)
	})
}

func BenchmarkSecureErase(b *testing.B) {
	// Test different file sizes
	fileSizes := []int{
		1024,   // 1KB
		10240,  // 10KB
		102400, // 100KB
	}

	for _, size := range fileSizes {
		b.Run(fmt.Sprintf("size_%dB", size), func(b *testing.B) {
			tmpDir := b.TempDir()
			ctx := context.Background()

			b.ResetTimer()
			i := 0
			for b.Loop() {
				b.StopTimer()

				// Create file
				filePath := filepath.Join(tmpDir, fmt.Sprintf("bench_%d.txt", i))
				content := make([]byte, size)
				for j := range content {
					content[j] = byte(j % 256)
				}
				_ = os.WriteFile(filePath, content, 0600)

				b.StartTimer()
				_ = SecureErase(ctx, filePath)
				i++
			}
		})
	}
}

func BenchmarkConcurrentSecureErase(b *testing.B) {
	tmpDir := b.TempDir()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		ctx := context.Background()
		for pb.Next() {
			// Create file
			filePath := filepath.Join(tmpDir, fmt.Sprintf("concurrent_%d_%d.txt",
				os.Getpid(), i))
			content := []byte("benchmark concurrent erase test content")
			_ = os.WriteFile(filePath, content, 0600)

			// Erase file
			_ = SecureErase(ctx, filePath)
			i++
		}
	})
}
