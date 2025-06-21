// Package architecture provides integration tests for helper migration
package architecture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/fileops"
	"go.uber.org/zap"
)

// TestHelperMigrationIntegration tests the migration from old helper functions to new domain services
func TestHelperMigrationIntegration(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewExample()

	// Create temporary test directory
	tempDir := t.TempDir()

	// Create application container
	container, err := CreateApplicationContainer(ctx, logger)
	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	t.Run("FileOperations_Service", func(t *testing.T) {
		// Get file operations service
		fileService, err := GetTyped[*fileops.Service](container, "fileops:service")
		if err != nil {
			t.Fatalf("Failed to get file service: %v", err)
		}

		// Test file operations
		testFile := filepath.Join(tempDir, "test.txt")
		testData := []byte("Hello, World!")

		// Test safe write
		if err := fileService.SafeWriteFile(ctx, testFile, testData, 0644); err != nil {
			t.Errorf("SafeWriteFile failed: %v", err)
		}

		// Verify file exists and has correct content
		fileOps, _ := GetTyped[fileops.FileOperations](container, "fileops:file_operations")
		readData, err := fileOps.ReadFile(ctx, testFile)
		if err != nil {
			t.Errorf("ReadFile failed: %v", err)
		}

		if string(readData) != string(testData) {
			t.Errorf("File content mismatch: got %s, want %s", string(readData), string(testData))
		}

		// Test copy with options
		copyFile := filepath.Join(tempDir, "copy.txt")
		opts := fileops.DefaultCopyOptions()
		result, err := fileService.CopyFileWithOptions(ctx, testFile, copyFile, opts)
		if err != nil {
			t.Errorf("CopyFileWithOptions failed: %v", err)
		}

		if !result.Success {
			t.Errorf("Copy operation not successful")
		}

		t.Logf("File operations test passed - copied %d bytes in %v",
			result.BytesWritten, result.Duration)
	})

	t.Run("Crypto_Service", func(t *testing.T) {
		// Get crypto service
		cryptoService, err := GetTyped[*crypto.Service](container, "crypto:service")
		if err != nil {
			t.Fatalf("Failed to get crypto service: %v", err)
		}

		// Test hashing
		testData := []byte("test data for hashing")
		hashResult, err := cryptoService.HashData(ctx, testData, crypto.SHA256)
		if err != nil {
			t.Errorf("HashData failed: %v", err)
		}

		if hashResult.Hash == "" {
			t.Errorf("Hash result is empty")
		}

		t.Logf("Hash computed: %s (took %v)", hashResult.Hash, hashResult.ComputeTime)

		// Test password generation and validation
		password, err := cryptoService.GenerateSecurePassword(ctx, 16)
		if err != nil {
			t.Errorf("GenerateSecurePassword failed: %v", err)
		}

		if len(password) < 16 {
			t.Errorf("Generated password too short: got %d chars, want at least 16", len(password))
		}

		// Test password validation
		if err := cryptoService.ValidatePassword(ctx, password); err != nil {
			t.Errorf("Generated password failed validation: %v", err)
		}

		t.Logf("Password generation and validation test passed")

		// Test encryption/decryption
		keyID := "test-key"
		plaintext := []byte("sensitive data to encrypt")

		encResult, err := cryptoService.EncryptData(ctx, plaintext, keyID)
		if err != nil {
			t.Errorf("EncryptData failed: %v", err)
		}

		if len(encResult.Ciphertext) == 0 {
			t.Errorf("Encryption produced empty ciphertext")
		}

		decResult, err := cryptoService.DecryptData(ctx, encResult.Ciphertext, keyID)
		if err != nil {
			t.Errorf("DecryptData failed: %v", err)
		}

		if string(decResult.Plaintext) != string(plaintext) {
			t.Errorf("Decryption failed: got %s, want %s",
				string(decResult.Plaintext), string(plaintext))
		}

		t.Logf("Encryption/decryption test passed - %d bytes encrypted/decrypted",
			len(plaintext))
	})

	t.Run("Template_Processing", func(t *testing.T) {
		// Get file operations service
		fileService, err := GetTyped[*fileops.Service](container, "fileops:service")
		if err != nil {
			t.Fatalf("Failed to get file service: %v", err)
		}

		// Create template directory
		templateDir := filepath.Join(tempDir, "templates")
		if err := os.MkdirAll(templateDir, 0755); err != nil {
			t.Fatalf("Failed to create template directory: %v", err)
		}

		// Create a template file
		templateFile := filepath.Join(templateDir, "config.tmpl")
		templateContent := `
app_name: {{APP_NAME}}
version: {{VERSION}}
debug: ${DEBUG}
`
		fileOps, _ := GetTyped[fileops.FileOperations](container, "fileops:file_operations")
		if err := fileOps.WriteFile(ctx, templateFile, []byte(templateContent), 0644); err != nil {
			t.Fatalf("Failed to write template file: %v", err)
		}

		// Process template
		data := fileops.TemplateData{
			Variables: map[string]string{
				"APP_NAME": "eos-test",
				"VERSION":  "1.0.0",
				"DEBUG":    "true",
			},
		}

		outputDir := filepath.Join(tempDir, "output")
		if err := fileService.ProcessTemplateDirectory(ctx, templateDir, outputDir, data, []string{"*.tmpl"}); err != nil {
			t.Errorf("ProcessTemplateDirectory failed: %v", err)
		}

		t.Logf("Template processing test passed")
	})

	t.Run("Directory_Operations", func(t *testing.T) {
		// Get file operations service
		fileService, err := GetTyped[*fileops.Service](container, "fileops:service")
		if err != nil {
			t.Fatalf("Failed to get file service: %v", err)
		}

		// Create test directory structure
		srcDir := filepath.Join(tempDir, "source")
		dstDir := filepath.Join(tempDir, "destination")

		if err := os.MkdirAll(srcDir, 0755); err != nil {
			t.Fatalf("Failed to create source directory: %v", err)
		}

		// Create some test files
		fileOps, _ := GetTyped[fileops.FileOperations](container, "fileops:file_operations")
		for i := 0; i < 3; i++ {
			filename := filepath.Join(srcDir, fmt.Sprintf("file%d.txt", i))
			content := fmt.Sprintf("Content of file %d", i)
			if err := fileOps.WriteFile(ctx, filename, []byte(content), 0644); err != nil {
				t.Fatalf("Failed to write test file: %v", err)
			}
		}

		// Test directory copy
		opts := fileops.DefaultCopyOptions()
		filter := fileops.DefaultFileFilter()

		batchResult, err := fileService.CopyDirectory(ctx, srcDir, dstDir, opts, filter)
		if err != nil {
			t.Errorf("CopyDirectory failed: %v", err)
		}

		if batchResult.SuccessfulFiles == 0 {
			t.Errorf("No files were copied successfully")
		}

		t.Logf("Directory copy test passed - %d files copied in %v",
			batchResult.SuccessfulFiles, batchResult.Duration)

		// Test directory info
		dirInfo, err := fileService.GetDirectoryInfo(ctx, dstDir)
		if err != nil {
			t.Errorf("GetDirectoryInfo failed: %v", err)
		}

		if dirInfo.FileCount != 3 {
			t.Errorf("Expected 3 files, got %d", dirInfo.FileCount)
		}

		t.Logf("Directory info test passed - found %d files, %d directories",
			dirInfo.FileCount, dirInfo.DirCount)
	})
}

// BenchmarkHelperMigration benchmarks the performance difference between old and new approaches
func BenchmarkHelperMigration(b *testing.B) {
	ctx := context.Background()
	logger := zap.NewExample()

	container, err := CreateApplicationContainer(ctx, logger)
	if err != nil {
		b.Fatalf("Failed to create container: %v", err)
	}

	cryptoService, err := GetTyped[*crypto.Service](container, "crypto:service")
	if err != nil {
		b.Fatalf("Failed to get crypto service: %v", err)
	}

	testData := []byte("benchmark test data for hashing performance comparison")

	b.Run("NewArchitecture_Hash", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := cryptoService.HashData(ctx, testData, crypto.SHA256)
			if err != nil {
				b.Fatalf("HashData failed: %v", err)
			}
		}
	})

	// This would be compared against direct crypto.HashString() calls
	// b.Run("OldHelpers_Hash", func(b *testing.B) {
	//     for i := 0; i < b.N; i++ {
	//         crypto.HashString(string(testData), "sha256")
	//     }
	// })
}
