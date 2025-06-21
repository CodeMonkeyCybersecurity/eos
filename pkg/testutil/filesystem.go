package testutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// =====================================
// File System Testing Utilities  
// =====================================

// TempDir creates a temporary directory for testing and ensures cleanup
func TempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return dir
}

// CreateTestFile creates a test file with specified content and permissions
func CreateTestFile(t *testing.T, dir, filename, content string, perm os.FileMode) string {
	t.Helper()
	filepath := filepath.Join(dir, filename)
	err := os.WriteFile(filepath, []byte(content), perm)
	AssertNoError(t, err)
	return filepath
}

// CreateTestDir creates a test directory with specified permissions
func CreateTestDir(t *testing.T, dir, dirname string, perm os.FileMode) string {
	t.Helper()
	dirpath := filepath.Join(dir, dirname)
	err := os.MkdirAll(dirpath, perm)
	AssertNoError(t, err)
	return dirpath
}

// AssertFileExists verifies that a file exists
func AssertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("expected file to exist: %s", path)
	}
}

// AssertFileNotExists verifies that a file does not exist
func AssertFileNotExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("expected file to not exist: %s", path)
	}
}

// AssertFilePermissions verifies file permissions
func AssertFilePermissions(t *testing.T, path string, expectedPerm os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	AssertNoError(t, err)
	actualPerm := info.Mode().Perm()
	if actualPerm != expectedPerm {
		t.Fatalf("expected permissions %o, got %o for file %s", expectedPerm, actualPerm, path)
	}
}

// AssertFileContent verifies file content matches expected
func AssertFileContent(t *testing.T, path, expected string) {
	t.Helper()
	content, err := os.ReadFile(path)
	AssertNoError(t, err)
	AssertEqual(t, expected, string(content))
}

// =====================================
// Environment Testing Utilities
// =====================================

// WithEnvVar temporarily sets an environment variable for the duration of a test
func WithEnvVar(t *testing.T, key, value string) func() {
	t.Helper()
	original := os.Getenv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("Failed to set environment variable %s: %v", key, err)
	}
	return func() {
		if original == "" {
			if err := os.Unsetenv(key); err != nil {
				t.Logf("Failed to unset environment variable %s: %v", key, err)
			}
		} else {
			if err := os.Setenv(key, original); err != nil {
				t.Logf("Failed to restore environment variable %s: %v", key, err)
			}
		}
	}
}

// WithoutEnvVar temporarily unsets an environment variable for the duration of a test
func WithoutEnvVar(t *testing.T, key string) func() {
	t.Helper()
	original := os.Getenv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("Failed to unset environment variable %s: %v", key, err)
	}
	return func() {
		if original != "" {
			if err := os.Setenv(key, original); err != nil {
				t.Logf("Failed to restore environment variable %s: %v", key, err)
			}
		}
	}
}

// SetupTestEnvironment creates a complete test environment with common variables
func SetupTestEnvironment(t *testing.T) func() {
	t.Helper()
	cleanups := []func(){}
	
	// Set test environment variables
	testVars := map[string]string{
		"EOS_TEST_MODE":     "true",
		"VAULT_ADDR":        "http://127.0.0.1:8200",
		"VAULT_SKIP_VERIFY": "true",
	}
	
	for key, value := range testVars {
		cleanup := WithEnvVar(t, key, value)
		cleanups = append(cleanups, cleanup)
	}
	
	return func() {
		for _, cleanup := range cleanups {
			cleanup()
		}
	}
}

// =====================================
// Time and Concurrency Testing Utilities
// =====================================

// Eventually runs a function repeatedly until it succeeds or times out
func Eventually(t *testing.T, condition func() bool, timeout time.Duration, interval time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(interval)
	}
	
	t.Fatalf("condition was not met within %v", timeout)
}

// Consistently runs a function repeatedly and ensures it consistently returns true
func Consistently(t *testing.T, condition func() bool, duration time.Duration, interval time.Duration) {
	t.Helper()
	deadline := time.Now().Add(duration)
	
	for time.Now().Before(deadline) {
		if !condition() {
			t.Fatal("condition failed during consistency check")
		}
		time.Sleep(interval)
	}
}

// ParallelTest runs a test function in parallel with the specified number of goroutines
func ParallelTest(t *testing.T, numGoroutines int, testFunc func(t *testing.T, workerID int)) {
	t.Helper()
	t.Parallel()
	
	done := make(chan bool, numGoroutines)
	
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer func() { done <- true }()
			testFunc(t, workerID)
		}(i)
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}