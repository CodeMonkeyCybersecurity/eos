package fileops_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/fileops"
	fileopsinfra "github.com/CodeMonkeyCybersecurity/eos/pkg/infrastructure/fileops"
)

func createTestService(t *testing.T) *fileops.Service {
	logger := zap.NewNop()

	fileOps := fileopsinfra.NewFileSystemOperations(logger)
	pathOps := fileopsinfra.NewPathOperations()
	templateOps := fileopsinfra.NewTemplateOperations(fileOps, pathOps, logger)
	safeOps := fileopsinfra.NewSafeFileOperations(fileOps, logger)

	return fileops.NewService(fileOps, pathOps, templateOps, safeOps, logger)
}

func createTestServiceForBenchmark(b *testing.B) *fileops.Service {
	logger := zap.NewNop()

	fileOps := fileopsinfra.NewFileSystemOperations(logger)
	pathOps := fileopsinfra.NewPathOperations()
	templateOps := fileopsinfra.NewTemplateOperations(fileOps, pathOps, logger)
	safeOps := fileopsinfra.NewSafeFileOperations(fileOps, logger)

	return fileops.NewService(fileOps, pathOps, templateOps, safeOps, logger)
}

func TestService_CopyFile(t *testing.T) {
	service := createTestService(t)
	ctx := context.Background()
	tempDir := t.TempDir()

	// Create source file
	srcPath := filepath.Join(tempDir, "source.txt")
	srcContent := []byte("test content")
	require.NoError(t, os.WriteFile(srcPath, srcContent, 0644))

	// Test copy
	dstPath := filepath.Join(tempDir, "destination.txt")
	err := service.CopyFile(ctx, srcPath, dstPath)
	assert.NoError(t, err)

	// Verify content
	dstContent, err := os.ReadFile(dstPath)
	assert.NoError(t, err)
	assert.Equal(t, srcContent, dstContent)
}

func TestService_CopyFileWithOptions(t *testing.T) {
	service := createTestService(t)
	ctx := context.Background()
	tempDir := t.TempDir()

	tests := []struct {
		name    string
		setup   func() (src, dst string)
		opts    fileops.CopyOptions
		wantErr bool
		verify  func(t *testing.T, result *fileops.FileOperationResult)
	}{
		{
			name: "copy with directory creation",
			setup: func() (src, dst string) {
				src = filepath.Join(tempDir, "source.txt")
				dst = filepath.Join(tempDir, "subdir", "dest.txt")
				require.NoError(t, os.WriteFile(src, []byte("test"), 0644))
				return src, dst
			},
			opts: fileops.CopyOptions{
				CreateDirs:  true,
				DefaultMode: 0755,
			},
			wantErr: false,
			verify: func(t *testing.T, result *fileops.FileOperationResult) {
				assert.True(t, result.Success)
				assert.Equal(t, int64(4), result.BytesWritten)
			},
		},
		{
			name: "copy preserving mode",
			setup: func() (src, dst string) {
				src = filepath.Join(tempDir, "executable.sh")
				dst = filepath.Join(tempDir, "copy.sh")
				require.NoError(t, os.WriteFile(src, []byte("#!/bin/bash"), 0755))
				return src, dst
			},
			opts: fileops.CopyOptions{
				PreserveMode: true,
			},
			wantErr: false,
			verify: func(t *testing.T, result *fileops.FileOperationResult) {
				info, err := os.Stat(result.Path)
				require.NoError(t, err)
				assert.Equal(t, os.FileMode(0755), info.Mode()&os.ModePerm)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, dst := tt.setup()

			result, err := service.CopyFileWithOptions(ctx, src, dst, tt.opts)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				tt.verify(t, result)
			}
		})
	}
}

func TestService_SafeWriteFile(t *testing.T) {
	service := createTestService(t)
	ctx := context.Background()
	tempDir := t.TempDir()

	// Test writing new file
	newPath := filepath.Join(tempDir, "new.txt")
	err := service.SafeWriteFile(ctx, newPath, []byte("new content"), 0644)
	assert.NoError(t, err)

	// Verify content
	content, err := os.ReadFile(newPath)
	assert.NoError(t, err)
	assert.Equal(t, "new content", string(content))

	// Test overwriting with backup
	err = service.SafeWriteFile(ctx, newPath, []byte("updated content"), 0644)
	assert.NoError(t, err)

	// Verify updated content
	content, err = os.ReadFile(newPath)
	assert.NoError(t, err)
	assert.Equal(t, "updated content", string(content))

	// Check backup was created
	files, err := os.ReadDir(tempDir)
	assert.NoError(t, err)

	backupFound := false
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".backup" {
			backupFound = true
			break
		}
	}
	assert.True(t, backupFound, "backup file should have been created")
}

func TestService_CopyDirectory(t *testing.T) {
	service := createTestService(t)
	ctx := context.Background()
	tempDir := t.TempDir()

	// Create source directory structure
	srcDir := filepath.Join(tempDir, "source")
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "subdir"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("file1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "subdir", "file2.txt"), []byte("file2"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, ".hidden"), []byte("hidden"), 0644))

	// Test copy without hidden files
	dstDir := filepath.Join(tempDir, "destination")
	opts := fileops.DefaultCopyOptions()
	filter := fileops.DefaultFileFilter()

	result, err := service.CopyDirectory(ctx, srcDir, dstDir, opts, filter)
	assert.NoError(t, err)
	assert.Equal(t, 2, result.SuccessfulFiles) // Only visible files

	// Verify structure
	assert.FileExists(t, filepath.Join(dstDir, "file1.txt"))
	assert.FileExists(t, filepath.Join(dstDir, "subdir", "file2.txt"))
	assert.NoFileExists(t, filepath.Join(dstDir, ".hidden"))
}

func TestService_DeleteFiles(t *testing.T) {
	service := createTestService(t)
	ctx := context.Background()
	tempDir := t.TempDir()

	// Create test files
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "delete1.tmp"), []byte("temp1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "delete2.tmp"), []byte("temp2"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "keep.txt"), []byte("keep"), 0644))

	// Delete only .tmp files
	filter := fileops.FileFilter{
		IncludePatterns: []string{"*.tmp"},
	}

	result, err := service.DeleteFiles(ctx, tempDir, filter)
	assert.NoError(t, err)
	assert.Equal(t, 2, result.SuccessfulFiles)
	assert.Equal(t, 0, result.FailedFiles)

	// Verify files
	assert.NoFileExists(t, filepath.Join(tempDir, "delete1.tmp"))
	assert.NoFileExists(t, filepath.Join(tempDir, "delete2.tmp"))
	assert.FileExists(t, filepath.Join(tempDir, "keep.txt"))
}

func TestService_ProcessTemplateDirectory(t *testing.T) {
	service := createTestService(t)
	ctx := context.Background()
	tempDir := t.TempDir()

	// Create template file
	templateContent := `Hello ${NAME}, your port is ${PORT}`
	templatePath := filepath.Join(tempDir, "config.tmpl")
	require.NoError(t, os.WriteFile(templatePath, []byte(templateContent), 0644))

	// Process templates
	data := fileops.TemplateData{
		Variables: map[string]string{
			"NAME": "TestApp",
			"PORT": "8080",
		},
	}

	err := service.ProcessTemplateDirectory(ctx, tempDir, tempDir, data, []string{"*.tmpl"})
	assert.NoError(t, err)

	// Verify processed content
	content, err := os.ReadFile(templatePath)
	assert.NoError(t, err)
	assert.Equal(t, "Hello TestApp, your port is 8080", string(content))
}

func TestService_GetDirectoryInfo(t *testing.T) {
	service := createTestService(t)
	ctx := context.Background()
	tempDir := t.TempDir()

	// Create test structure
	require.NoError(t, os.MkdirAll(filepath.Join(tempDir, "dir1"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(tempDir, "dir2"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "file1.txt"), []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "file2.txt"), []byte("content2"), 0644))

	// Get directory info
	info, err := service.GetDirectoryInfo(ctx, tempDir)
	assert.NoError(t, err)
	assert.Equal(t, 2, info.FileCount)
	assert.Equal(t, 2, info.DirCount)
	assert.Equal(t, int64(16), info.TotalSize) // "content1" + "content2"
}

func TestService_BatchCopy(t *testing.T) {
	service := createTestService(t)
	ctx := context.Background()
	tempDir := t.TempDir()

	// Create source files
	operations := []struct{ Src, Dst string }{
		{
			Src: filepath.Join(tempDir, "src1.txt"),
			Dst: filepath.Join(tempDir, "dst1.txt"),
		},
		{
			Src: filepath.Join(tempDir, "src2.txt"),
			Dst: filepath.Join(tempDir, "dst2.txt"),
		},
	}

	for _, op := range operations {
		require.NoError(t, os.WriteFile(op.Src, []byte("content"), 0644))
	}

	// Perform batch copy
	result, err := service.BatchCopy(ctx, operations, fileops.DefaultCopyOptions())
	assert.NoError(t, err)
	assert.Equal(t, 2, result.SuccessfulFiles)
	assert.Equal(t, 0, result.FailedFiles)
	assert.Equal(t, 100.0, result.SuccessRate())

	// Verify all files copied
	for _, op := range operations {
		assert.FileExists(t, op.Dst)
	}
}

func BenchmarkService_CopyFile(b *testing.B) {
	service := createTestServiceForBenchmark(b)
	ctx := context.Background()
	tempDir := b.TempDir()

	// Create 1MB source file
	srcPath := filepath.Join(tempDir, "source.dat")
	data := make([]byte, 1024*1024)
	require.NoError(b, os.WriteFile(srcPath, data, 0644))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dstPath := filepath.Join(tempDir, fmt.Sprintf("dest_%d.dat", i))
		err := service.CopyFile(ctx, srcPath, dstPath)
		if err != nil {
			b.Fatal(err)
		}
	}
}
