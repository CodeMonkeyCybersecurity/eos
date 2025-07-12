package shared

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Common file operation utilities to reduce duplication across the codebase

// FileExists checks if a file or directory exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// DirectoryExists checks if a directory exists
func DirectoryExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// IsRegularFile checks if a path exists and is a regular file
func IsRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// EnsureDirectoryExists creates a directory if it doesn't exist
func EnsureDirectoryExists(path string, perm os.FileMode) error {
	if path == "" {
		return fmt.Errorf("directory path cannot be empty")
	}
	
	if DirectoryExists(path) {
		return nil
	}
	
	if err := os.MkdirAll(path, perm); err != nil {
		return WrapFileOperationError("create directory", path, err)
	}
	
	return nil
}

// EnsureFileDirectoryExists creates the parent directory of a file if it doesn't exist
func EnsureFileDirectoryExists(filePath string, perm os.FileMode) error {
	dir := filepath.Dir(filePath)
	return EnsureDirectoryExists(dir, perm)
}

// CheckFilePermissions verifies that a file has the expected permissions
func CheckFilePermissions(path string, expectedPerm os.FileMode) error {
	if !FileExists(path) {
		return fmt.Errorf("file does not exist: %s", path)
	}
	
	info, err := os.Stat(path)
	if err != nil {
		return WrapFileOperationError("check permissions", path, err)
	}
	
	actualPerm := info.Mode().Perm()
	if actualPerm != expectedPerm {
		return fmt.Errorf("file %s has permissions %o, expected %o", path, actualPerm, expectedPerm)
	}
	
	return nil
}

// SetFilePermissions sets the permissions on a file or directory
func SetFilePermissions(path string, perm os.FileMode) error {
	if !FileExists(path) {
		return fmt.Errorf("file does not exist: %s", path)
	}
	
	if err := os.Chmod(path, perm); err != nil {
		return WrapFileOperationError("set permissions", path, err)
	}
	
	return nil
}

// CopyFile copies a file from source to destination
func CopyFile(src, dst string) error {
	if !FileExists(src) {
		return fmt.Errorf("source file does not exist: %s", src)
	}
	
	// Ensure destination directory exists
	if err := EnsureFileDirectoryExists(dst, 0755); err != nil {
		return err
	}
	
	// Open source file
	srcFile, err := os.Open(src)
	if err != nil {
		return WrapFileOperationError("open source", src, err)
	}
	defer srcFile.Close()
	
	// Create destination file
	dstFile, err := os.Create(dst)
	if err != nil {
		return WrapFileOperationError("create destination", dst, err)
	}
	defer dstFile.Close()
	
	// Copy contents
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return WrapFileOperationError("copy", fmt.Sprintf("%s to %s", src, dst), err)
	}
	
	// Copy permissions
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return WrapFileOperationError("get source info", src, err)
	}
	
	if err := dstFile.Chmod(srcInfo.Mode()); err != nil {
		return WrapFileOperationError("set destination permissions", dst, err)
	}
	
	return nil
}

// MoveFile moves a file from source to destination
func MoveFile(src, dst string) error {
	if !FileExists(src) {
		return fmt.Errorf("source file does not exist: %s", src)
	}
	
	// Ensure destination directory exists
	if err := EnsureFileDirectoryExists(dst, 0755); err != nil {
		return err
	}
	
	// Try rename first (works if on same filesystem)
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	
	// If rename fails, copy and delete
	if err := CopyFile(src, dst); err != nil {
		return err
	}
	
	if err := os.Remove(src); err != nil {
		return WrapFileOperationError("remove source after move", src, err)
	}
	
	return nil
}

// BackupFile creates a backup of a file with timestamp
func BackupFile(path string) (string, error) {
	if !FileExists(path) {
		return "", fmt.Errorf("file does not exist: %s", path)
	}
	
	timestamp := time.Now().Format("20060102_150405")
	backupPath := fmt.Sprintf("%s.backup_%s", path, timestamp)
	
	if err := CopyFile(path, backupPath); err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}
	
	return backupPath, nil
}

// RestoreFromBackup restores a file from its backup
func RestoreFromBackup(originalPath, backupPath string) error {
	if !FileExists(backupPath) {
		return fmt.Errorf("backup file does not exist: %s", backupPath)
	}
	
	if err := CopyFile(backupPath, originalPath); err != nil {
		return fmt.Errorf("failed to restore from backup: %w", err)
	}
	
	return nil
}

// ReadFileContents reads the entire contents of a file
func ReadFileContents(path string) ([]byte, error) {
	if !FileExists(path) {
		return nil, fmt.Errorf("file does not exist: %s", path)
	}
	
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, WrapFileOperationError("read", path, err)
	}
	
	return content, nil
}

// WriteFileContents writes content to a file
func WriteFileContents(path string, content []byte, perm os.FileMode) error {
	// Ensure directory exists
	if err := EnsureFileDirectoryExists(path, 0755); err != nil {
		return err
	}
	
	if err := os.WriteFile(path, content, perm); err != nil {
		return WrapFileOperationError("write", path, err)
	}
	
	return nil
}

// AppendToFile appends content to a file
func AppendToFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return WrapFileOperationError("open for append", path, err)
	}
	defer file.Close()
	
	if _, err := file.Write(content); err != nil {
		return WrapFileOperationError("append", path, err)
	}
	
	return nil
}

// GetFileSize returns the size of a file in bytes
func GetFileSize(path string) (int64, error) {
	if !FileExists(path) {
		return 0, fmt.Errorf("file does not exist: %s", path)
	}
	
	info, err := os.Stat(path)
	if err != nil {
		return 0, WrapFileOperationError("get file info", path, err)
	}
	
	return info.Size(), nil
}

// GetFileHash calculates SHA256 hash of a file
func GetFileHash(path string) (string, error) {
	if !FileExists(path) {
		return "", fmt.Errorf("file does not exist: %s", path)
	}
	
	file, err := os.Open(path)
	if err != nil {
		return "", WrapFileOperationError("open for hashing", path, err)
	}
	defer file.Close()
	
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", WrapFileOperationError("calculate hash", path, err)
	}
	
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// CompareFiles compares two files and returns true if they are identical
func CompareFiles(path1, path2 string) (bool, error) {
	if !FileExists(path1) {
		return false, fmt.Errorf("first file does not exist: %s", path1)
	}
	if !FileExists(path2) {
		return false, fmt.Errorf("second file does not exist: %s", path2)
	}
	
	// Compare file sizes first
	info1, err := os.Stat(path1)
	if err != nil {
		return false, WrapFileOperationError("get info", path1, err)
	}
	
	info2, err := os.Stat(path2)
	if err != nil {
		return false, WrapFileOperationError("get info", path2, err)
	}
	
	if info1.Size() != info2.Size() {
		return false, nil
	}
	
	// Compare hashes
	hash1, err := GetFileHash(path1)
	if err != nil {
		return false, err
	}
	
	hash2, err := GetFileHash(path2)
	if err != nil {
		return false, err
	}
	
	return hash1 == hash2, nil
}

// FindFiles recursively finds files matching a pattern
func FindFiles(rootDir, pattern string) ([]string, error) {
	if !DirectoryExists(rootDir) {
		return nil, fmt.Errorf("directory does not exist: %s", rootDir)
	}
	
	var matchedFiles []string
	
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if info.IsDir() {
			return nil
		}
		
		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err != nil {
			return err
		}
		
		if matched {
			matchedFiles = append(matchedFiles, path)
		}
		
		return nil
	})
	
	if err != nil {
		return nil, WrapFileOperationError("search files", rootDir, err)
	}
	
	return matchedFiles, nil
}

// CleanupOldFiles removes files older than the specified duration
func CleanupOldFiles(dir string, maxAge time.Duration, pattern string) error {
	if !DirectoryExists(dir) {
		return fmt.Errorf("directory does not exist: %s", dir)
	}
	
	cutoff := time.Now().Add(-maxAge)
	
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if info.IsDir() {
			return nil
		}
		
		// Check pattern if provided
		if pattern != "" {
			matched, err := filepath.Match(pattern, filepath.Base(path))
			if err != nil {
				return err
			}
			if !matched {
				return nil
			}
		}
		
		// Check age
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(path); err != nil {
				return WrapFileOperationError("remove old file", path, err)
			}
		}
		
		return nil
	})
}

// SafeWriteFile writes to a temporary file first, then moves to final location
func SafeWriteFile(path string, content []byte, perm os.FileMode) error {
	// Create temporary file in same directory
	dir := filepath.Dir(path)
	if err := EnsureDirectoryExists(dir, 0755); err != nil {
		return err
	}
	
	tmpFile, err := os.CreateTemp(dir, ".tmp_"+filepath.Base(path)+"_*")
	if err != nil {
		return WrapFileOperationError("create temporary file", path, err)
	}
	tmpPath := tmpFile.Name()
	
	// Clean up temp file on error
	defer func() {
		if FileExists(tmpPath) {
			os.Remove(tmpPath)
		}
	}()
	
	// Write content to temp file
	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		return WrapFileOperationError("write to temporary file", tmpPath, err)
	}
	
	// Set permissions
	if err := tmpFile.Chmod(perm); err != nil {
		tmpFile.Close()
		return WrapFileOperationError("set permissions on temporary file", tmpPath, err)
	}
	
	// Close temp file
	if err := tmpFile.Close(); err != nil {
		return WrapFileOperationError("close temporary file", tmpPath, err)
	}
	
	// Atomic move to final location
	if err := os.Rename(tmpPath, path); err != nil {
		return WrapFileOperationError("move temporary file to final location", path, err)
	}
	
	return nil
}

// GetDiskUsage returns disk usage information for a path
func GetDiskUsage(path string) (total, free, used uint64, err error) {
	// This is a simplified implementation
	// In a real implementation, you'd use syscalls to get actual disk usage
	return 0, 0, 0, fmt.Errorf("disk usage not implemented")
}

// IsExecutable checks if a file is executable
func IsExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	
	mode := info.Mode()
	return mode&0111 != 0 // Check if any execute bit is set
}

// MakeExecutable makes a file executable
func MakeExecutable(path string) error {
	if !FileExists(path) {
		return fmt.Errorf("file does not exist: %s", path)
	}
	
	info, err := os.Stat(path)
	if err != nil {
		return WrapFileOperationError("get file info", path, err)
	}
	
	// Add execute permission for owner, group, and others
	newMode := info.Mode() | 0111
	
	if err := os.Chmod(path, newMode); err != nil {
		return WrapFileOperationError("make executable", path, err)
	}
	
	return nil
}

// SecureDelete overwrites a file before deleting it
func SecureDelete(path string) error {
	if !FileExists(path) {
		return fmt.Errorf("file does not exist: %s", path)
	}
	
	// Get file size
	size, err := GetFileSize(path)
	if err != nil {
		return err
	}
	
	// Open file for writing
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return WrapFileOperationError("open for secure delete", path, err)
	}
	defer file.Close()
	
	// Overwrite with zeros
	zeros := make([]byte, 1024)
	remaining := size
	
	for remaining > 0 {
		writeSize := int64(len(zeros))
		if remaining < writeSize {
			writeSize = remaining
		}
		
		if _, err := file.Write(zeros[:writeSize]); err != nil {
			return WrapFileOperationError("overwrite for secure delete", path, err)
		}
		
		remaining -= writeSize
	}
	
	// Sync to disk
	if err := file.Sync(); err != nil {
		return WrapFileOperationError("sync for secure delete", path, err)
	}
	
	// Close and delete
	file.Close()
	if err := os.Remove(path); err != nil {
		return WrapFileOperationError("remove after secure delete", path, err)
	}
	
	return nil
}

// IsPathSafe checks if a path is safe (no directory traversal)
func IsPathSafe(basePath, targetPath string) bool {
	// Clean and make absolute
	basePath = filepath.Clean(basePath)
	targetPath = filepath.Clean(targetPath)
	
	// Check if target is within base
	rel, err := filepath.Rel(basePath, targetPath)
	if err != nil {
		return false
	}
	
	// Check for directory traversal
	return !strings.HasPrefix(rel, "..") && !strings.Contains(rel, "/../")
}