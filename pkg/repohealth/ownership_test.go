// pkg/repohealth/ownership_test.go

package repohealth

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditOwnership_CleanRepo(t *testing.T) {
	// Create a temp directory (owned by current user)
	tmpDir := t.TempDir()

	// Create subdirectories and files
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "pkg", "foo"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "cmd"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "pkg", "foo", "bar.go"), []byte("package foo"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "cmd", "main.go"), []byte("package main"), 0644))

	report, err := AuditOwnership(tmpDir)
	require.NoError(t, err)

	assert.False(t, report.HasIssues(), "clean temp dir should have no ownership issues")
	assert.Equal(t, 0, report.TotalMismatched())
	assert.Greater(t, report.TotalScanned, 0, "should have scanned files")
	assert.Contains(t, report.Summary(), "ownership check passed")
}

func TestAuditOwnership_SkipsGitAndVendor(t *testing.T) {
	tmpDir := t.TempDir()

	// Create .git and vendor directories
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, ".git", "objects"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "vendor", "github.com"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "src"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".git", "objects", "pack"), []byte("data"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "vendor", "github.com", "lib.go"), []byte("package lib"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "src", "main.go"), []byte("package main"), 0644))

	report, err := AuditOwnership(tmpDir)
	require.NoError(t, err)

	// .git and vendor should be skipped, so only tmpDir + src/ + src/main.go scanned
	for _, f := range report.MismatchedFiles {
		assert.NotContains(t, f.Path, ".git", "should not scan .git directory")
		assert.NotContains(t, f.Path, "vendor", "should not scan vendor directory")
	}
	for _, d := range report.MismatchedDirs {
		assert.NotContains(t, d.Path, ".git", "should not scan .git directory")
		assert.NotContains(t, d.Path, "vendor", "should not scan vendor directory")
	}
}

func TestAuditOwnership_NonexistentDir(t *testing.T) {
	_, err := AuditOwnership("/nonexistent/path/to/repo")
	assert.Error(t, err, "should error for nonexistent directory")
}

func TestOwnershipReport_HasIssues(t *testing.T) {
	tests := []struct {
		name     string
		report   OwnershipReport
		expected bool
	}{
		{
			name:     "no issues",
			report:   OwnershipReport{},
			expected: false,
		},
		{
			name: "mismatched files only",
			report: OwnershipReport{
				MismatchedFiles: []MismatchedFile{{Path: "/foo", ActualUID: 0}},
			},
			expected: true,
		},
		{
			name: "mismatched dirs only",
			report: OwnershipReport{
				MismatchedDirs: []MismatchedFile{{Path: "/bar", ActualUID: 0}},
			},
			expected: true,
		},
		{
			name: "both mismatched",
			report: OwnershipReport{
				MismatchedFiles: []MismatchedFile{{Path: "/foo", ActualUID: 0}},
				MismatchedDirs:  []MismatchedFile{{Path: "/bar", ActualUID: 0}},
			},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.report.HasIssues())
		})
	}
}

func TestOwnershipReport_TotalMismatched(t *testing.T) {
	report := OwnershipReport{
		MismatchedFiles: []MismatchedFile{{Path: "/a"}, {Path: "/b"}},
		MismatchedDirs:  []MismatchedFile{{Path: "/c"}},
	}
	assert.Equal(t, 3, report.TotalMismatched())
}

func TestOwnershipReport_Summary(t *testing.T) {
	t.Run("clean report", func(t *testing.T) {
		report := &OwnershipReport{
			TotalScanned: 42,
			ExpectedUser: "henry",
		}
		summary := report.Summary()
		assert.Contains(t, summary, "passed")
		assert.Contains(t, summary, "42")
		assert.Contains(t, summary, "henry")
	})

	t.Run("report with issues", func(t *testing.T) {
		report := &OwnershipReport{
			RepoRoot:        "/opt/eos",
			TotalScanned:    100,
			ExpectedUser:    "henry",
			MismatchedFiles: []MismatchedFile{{Path: "/opt/eos/go.mod", ActualUID: 0}},
			MismatchedDirs:  []MismatchedFile{{Path: "/opt/eos/test/e2e", ActualUID: 0}},
		}
		summary := report.Summary()
		assert.Contains(t, summary, "FAILED")
		assert.Contains(t, summary, "sudo chown -R henry:henry /opt/eos")
		assert.Contains(t, summary, "directories with wrong owner: 1")
	})
}

func TestOwnershipReport_FixCommand(t *testing.T) {
	report := &OwnershipReport{
		RepoRoot:     "/opt/eos",
		ExpectedUser: "henry",
	}
	assert.Equal(t, "sudo chown -R henry:henry /opt/eos", report.FixCommand())
}

func TestDetectRepoRoot_NotARepo(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := DetectRepoRoot(tmpDir)
	assert.Error(t, err, "temp dir without .git should fail")
}

func TestQuickCheck_CleanDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create the directories that QuickCheck looks for
	for _, dir := range []string{"test", "pkg", "cmd", "scripts", "assets"} {
		require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, dir), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, dir, "file.go"), []byte("package x"), 0644))
	}

	hasIssues, err := QuickCheck(tmpDir)
	require.NoError(t, err)
	assert.False(t, hasIssues, "clean temp dir should have no issues")
}

func TestQuickCheck_NonexistentDir(t *testing.T) {
	_, err := QuickCheck("/nonexistent")
	assert.Error(t, err)
}

func TestAuditOwnership_RelativePath(t *testing.T) {
	// Create temp dir and verify it works with the absolute path resolution
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "file.go"), []byte("package x"), 0644))

	report, err := AuditOwnership(tmpDir)
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(report.RepoRoot), "RepoRoot should be absolute")
}

func TestMismatchedFile_Fields(t *testing.T) {
	mf := MismatchedFile{
		Path:      "/opt/eos/test/e2e/framework.go",
		ActualUID: 0,
		ActualGID: 0,
	}
	assert.Equal(t, "/opt/eos/test/e2e/framework.go", mf.Path)
	assert.Equal(t, uint32(0), mf.ActualUID)
	assert.Equal(t, uint32(0), mf.ActualGID)
}

func TestAuditOwnership_CorrectUIDDetection(t *testing.T) {
	tmpDir := t.TempDir()

	// Get current user's UID
	info, err := os.Stat(tmpDir)
	require.NoError(t, err)
	stat := info.Sys().(*syscall.Stat_t)

	report, err := AuditOwnership(tmpDir)
	require.NoError(t, err)

	assert.Equal(t, stat.Uid, report.ExpectedUID, "should detect UID from repo root")
	assert.Equal(t, stat.Gid, report.ExpectedGID, "should detect GID from repo root")
}

func TestSkipDirs(t *testing.T) {
	expected := map[string]bool{
		".git":         true,
		"vendor":       true,
		"node_modules": true,
	}
	assert.Equal(t, expected, skipDirs)
}

func TestOwnershipReport_EmptyRepoRoot(t *testing.T) {
	report := &OwnershipReport{
		ExpectedUser:    "test",
		MismatchedFiles: []MismatchedFile{{Path: "/foo"}},
	}
	// FixCommand should still work even with empty RepoRoot
	cmd := report.FixCommand()
	assert.Contains(t, cmd, "sudo chown")
}

func TestAuditOwnership_WithNodeModules(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "node_modules", ".package-lock.json"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "node_modules", "file.js"), []byte("x"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0644))

	report, err := AuditOwnership(tmpDir)
	require.NoError(t, err)

	for _, f := range report.MismatchedFiles {
		assert.NotContains(t, f.Path, "node_modules")
	}
}

func TestOwnershipReport_SummaryFormatting(t *testing.T) {
	// Verify summary contains actionable information
	report := &OwnershipReport{
		RepoRoot:        "/opt/eos",
		TotalScanned:    1000,
		ExpectedUser:    "developer",
		MismatchedFiles: make([]MismatchedFile, 50),
		MismatchedDirs:  make([]MismatchedFile, 5),
	}

	summary := report.Summary()
	assert.Contains(t, summary, "55 mismatched out of 1000 scanned")
	assert.Contains(t, summary, "directories with wrong owner: 5")
	assert.Contains(t, summary, "files with wrong owner: 50")
	assert.Contains(t, summary, "sudo chown -R developer:developer /opt/eos")
}

func TestQuickCheck_MissingSubdirectories(t *testing.T) {
	// QuickCheck should handle missing subdirectories gracefully
	tmpDir := t.TempDir()
	// Don't create any of the expected subdirs (test, pkg, cmd, etc.)

	hasIssues, err := QuickCheck(tmpDir)
	require.NoError(t, err)
	assert.False(t, hasIssues, "missing subdirs should not be reported as issues")
}

func TestAuditOwnership_LargeFileCount(t *testing.T) {
	tmpDir := t.TempDir()

	// Create 100 files to verify scanning handles volume
	for i := 0; i < 100; i++ {
		require.NoError(t, os.WriteFile(
			filepath.Join(tmpDir, fmt.Sprintf("file_%03d.go", i)),
			[]byte("package test"),
			0644,
		))
	}

	report, err := AuditOwnership(tmpDir)
	require.NoError(t, err)

	// tmpDir itself + 100 files = 101 scanned
	assert.Equal(t, 101, report.TotalScanned)
	assert.False(t, report.HasIssues())
}
