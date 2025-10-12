// pkg/vault/binary_cleanup_test.go

package vault

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func TestFindVaultBinaries(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// This test will find actual binaries on the system
	// It's more of an integration test
	binaries, err := findVaultBinaries(rc)
	if err != nil {
		t.Fatalf("Failed to find binaries: %v", err)
	}

	// Log what we found
	t.Logf("Found %d vault binaries on system:", len(binaries))
	for i, binary := range binaries {
		t.Logf("  %d. %s (version: %s, symlink: %v)",
			i+1, binary.Path, binary.Version, binary.IsSymlink)
		if binary.IsSymlink {
			t.Logf("     -> %s", binary.LinkTarget)
		}
	}

	// Basic sanity checks
	for _, binary := range binaries {
		if binary.Path == "" {
			t.Error("Binary path should not be empty")
		}
	}
}

func TestVerifyBinaryIntegrity(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		setupFunc   func() string // Returns binary path
		expectError bool
		description string
	}{
		{
			name: "binary_not_exists",
			setupFunc: func() string {
				return filepath.Join(tmpDir, "nonexistent")
			},
			expectError: true,
			description: "Non-existent binary should fail verification",
		},
		{
			name: "binary_not_executable",
			setupFunc: func() string {
				path := filepath.Join(tmpDir, "not_executable")
				_ = os.WriteFile(path, []byte("#!/bin/sh\necho test"), 0644) // No execute bit
				return path
			},
			expectError: true,
			description: "Non-executable file should fail verification",
		},
		{
			name: "binary_empty",
			setupFunc: func() string {
				path := filepath.Join(tmpDir, "empty")
				_ = os.WriteFile(path, []byte(""), 0755)
				return path
			},
			expectError: true,
			description: "Empty binary should fail verification",
		},
		{
			name: "binary_not_vault",
			setupFunc: func() string {
				path := filepath.Join(tmpDir, "fake_vault")
				_ = os.WriteFile(path, []byte("#!/bin/sh\nexit 1"), 0755)
				return path
			},
			expectError: true,
			description: "Binary that fails to execute should fail verification",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binaryPath := tt.setupFunc()

			err := VerifyBinaryIntegrity(rc, binaryPath)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			t.Logf("Verification result: %v", err)
		})
	}
}

func TestCleanupDuplicateBinaries(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tmpDir := t.TempDir()

	// Create test binaries
	primaryPath := filepath.Join(tmpDir, "primary", "vault")
	duplicatePath1 := filepath.Join(tmpDir, "duplicate1", "vault")
	duplicatePath2 := filepath.Join(tmpDir, "duplicate2", "vault")

	// Setup directories
	_ = os.MkdirAll(filepath.Dir(primaryPath), 0755)
	_ = os.MkdirAll(filepath.Dir(duplicatePath1), 0755)
	_ = os.MkdirAll(filepath.Dir(duplicatePath2), 0755)

	// Create mock binaries
	mockBinary := []byte("#!/bin/sh\necho 'Vault v1.0.0'")
	_ = os.WriteFile(primaryPath, mockBinary, 0755)
	_ = os.WriteFile(duplicatePath1, mockBinary, 0755)
	_ = os.WriteFile(duplicatePath2, mockBinary, 0755)

	// Create test binaries slice
	binaries := []BinaryLocation{
		{Path: primaryPath, Version: "v1.0.0", Size: int64(len(mockBinary))},
		{Path: duplicatePath1, Version: "v1.0.0", Size: int64(len(mockBinary))},
		{Path: duplicatePath2, Version: "v1.0.0", Size: int64(len(mockBinary))},
	}

	// Test removal
	removed, err := removeDuplicates(rc, binaries, primaryPath)
	if err != nil {
		t.Fatalf("Failed to remove duplicates: %v", err)
	}

	// Verify results
	if removed != 2 {
		t.Errorf("Expected 2 binaries removed, got %d", removed)
	}

	// Verify primary still exists
	if _, err := os.Stat(primaryPath); err != nil {
		t.Errorf("Primary binary should still exist: %v", err)
	}

	// Verify duplicates were removed
	if _, err := os.Stat(duplicatePath1); !os.IsNotExist(err) {
		t.Error("Duplicate 1 should be removed")
	}
	if _, err := os.Stat(duplicatePath2); !os.IsNotExist(err) {
		t.Error("Duplicate 2 should be removed")
	}

	t.Logf("Successfully removed %d duplicate binaries", removed)
}

func TestRemoveDuplicatesWithSymlinks(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tmpDir := t.TempDir()

	// Create real binary
	realPath := filepath.Join(tmpDir, "real", "vault")
	symlinkPath := filepath.Join(tmpDir, "link", "vault")

	_ = os.MkdirAll(filepath.Dir(realPath), 0755)
	_ = os.MkdirAll(filepath.Dir(symlinkPath), 0755)

	// Create real binary
	mockBinary := []byte("#!/bin/sh\necho 'Vault v1.0.0'")
	_ = os.WriteFile(realPath, mockBinary, 0755)

	// Create symlink
	if err := os.Symlink(realPath, symlinkPath); err != nil {
		t.Skipf("Cannot create symlink (may not have permissions): %v", err)
	}

	binaries := []BinaryLocation{
		{
			Path:       realPath,
			Version:    "v1.0.0",
			Size:       int64(len(mockBinary)),
			IsSymlink:  false,
		},
		{
			Path:       symlinkPath,
			Version:    "v1.0.0",
			Size:       int64(len(mockBinary)),
			IsSymlink:  true,
			LinkTarget: realPath,
		},
	}

	// Remove duplicates, keeping real path
	removed, err := removeDuplicates(rc, binaries, realPath)
	if err != nil {
		t.Fatalf("Failed to remove duplicates: %v", err)
	}

	// Should remove symlink
	if removed != 1 {
		t.Errorf("Expected 1 symlink removed, got %d", removed)
	}

	// Real binary should exist
	if _, err := os.Stat(realPath); err != nil {
		t.Error("Real binary should still exist")
	}

	// Symlink should be removed
	if _, err := os.Lstat(symlinkPath); !os.IsNotExist(err) {
		t.Error("Symlink should be removed")
	}

	t.Logf("Successfully removed symlink, kept real binary")
}

func TestRecommendBinaryCleanup(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// This is more of an integration test - it will analyze the actual system
	recommendations, err := RecommendBinaryCleanup(rc)
	if err != nil {
		t.Fatalf("Failed to get recommendations: %v", err)
	}

	if len(recommendations) == 0 {
		t.Error("Should return at least one recommendation")
	}

	t.Log("Binary cleanup recommendations:")
	for i, rec := range recommendations {
		t.Logf("  %d. %s", i+1, rec)
	}
}

func TestDisplayBinaryFindings(t *testing.T) {
	binaries := []BinaryLocation{
		{
			Path:      "/usr/local/bin/vault",
			Version:   "Vault v1.15.0",
			Size:      123456789,
			IsSymlink: false,
		},
		{
			Path:       "/usr/bin/vault",
			Version:    "Vault v1.14.0",
			Size:       112233445,
			IsSymlink:  true,
			LinkTarget: "/opt/vault/bin/vault",
		},
	}

	// This test just verifies it doesn't crash
	// Output will go to stdout (visible in test output)
	displayBinaryFindings(binaries, "/usr/local/bin/vault")

	t.Log("Display function executed without errors")
}

func TestBinaryLocationStruct(t *testing.T) {
	binary := BinaryLocation{
		Path:       "/usr/local/bin/vault",
		Version:    "Vault v1.15.0",
		Size:       123456789,
		IsSymlink:  false,
		LinkTarget: "",
	}

	if binary.Path != "/usr/local/bin/vault" {
		t.Errorf("Unexpected path: %s", binary.Path)
	}
	if binary.IsSymlink {
		t.Error("Should not be a symlink")
	}
	if binary.LinkTarget != "" {
		t.Error("Link target should be empty for non-symlink")
	}

	t.Logf("Binary location: %+v", binary)
}

func TestCleanupWithNoMultipleBinaries(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tmpDir := t.TempDir()
	singlePath := filepath.Join(tmpDir, "vault")

	// Create single binary
	_ = os.WriteFile(singlePath, []byte("#!/bin/sh\necho test"), 0755)

	binaries := []BinaryLocation{
		{Path: singlePath, Version: "v1.0.0"},
	}

	// Cleanup with single binary should remove nothing
	removed, err := removeDuplicates(rc, binaries, singlePath)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if removed != 0 {
		t.Errorf("Should not remove anything, removed %d", removed)
	}

	// Binary should still exist
	if _, err := os.Stat(singlePath); err != nil {
		t.Error("Binary should still exist")
	}

	t.Log("Correctly handled single binary case")
}
