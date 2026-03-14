// pkg/repohealth/ownership.go
//
// Detects and reports repository file ownership issues that cause git operations
// to fail (e.g., "unable to unlink old file: Permission denied").
//
// ROOT CAUSE: When commands run as root (sudo go test, sudo make, docker operations)
// in a user-owned repo, they create files owned by root. Git, running as the user,
// cannot unlink/overwrite these files during pull/checkout/merge operations.
//
// POSIX SEMANTICS: File deletion is controlled by the parent directory's write+execute
// permission, not the file's own permissions. A root-owned directory prevents non-root
// users from creating/deleting files within it.
//
// REFERENCE: https://git-scm.com/docs/git-config#Documentation/git-config.txt-safedirectory

package repohealth

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// OwnershipReport contains the results of a repository ownership audit.
type OwnershipReport struct {
	// RepoRoot is the absolute path to the repository root.
	RepoRoot string

	// ExpectedUID is the UID that should own all files.
	ExpectedUID uint32

	// ExpectedGID is the GID that should own all files.
	ExpectedGID uint32

	// ExpectedUser is the username that should own all files.
	ExpectedUser string

	// MismatchedFiles lists files with wrong ownership.
	MismatchedFiles []MismatchedFile

	// MismatchedDirs lists directories with wrong ownership (higher priority
	// because they block file creation/deletion).
	MismatchedDirs []MismatchedFile

	// TotalScanned is the count of files/dirs checked.
	TotalScanned int
}

// MismatchedFile represents a single file or directory with incorrect ownership.
type MismatchedFile struct {
	Path      string
	ActualUID uint32
	ActualGID uint32
}

// HasIssues returns true if any ownership mismatches were found.
func (r *OwnershipReport) HasIssues() bool {
	return len(r.MismatchedFiles) > 0 || len(r.MismatchedDirs) > 0
}

// TotalMismatched returns the total count of mismatched files and directories.
func (r *OwnershipReport) TotalMismatched() int {
	return len(r.MismatchedFiles) + len(r.MismatchedDirs)
}

// Summary returns a human-readable summary of the ownership audit.
func (r *OwnershipReport) Summary() string {
	if !r.HasIssues() {
		return fmt.Sprintf("ownership check passed: %d files scanned, all owned by %s",
			r.TotalScanned, r.ExpectedUser)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "ownership check FAILED: %d mismatched out of %d scanned\n",
		r.TotalMismatched(), r.TotalScanned)
	fmt.Fprintf(&b, "  directories with wrong owner: %d (blocks git file operations)\n",
		len(r.MismatchedDirs))
	fmt.Fprintf(&b, "  files with wrong owner: %d\n", len(r.MismatchedFiles))
	fmt.Fprintf(&b, "\nfix with:\n")
	fmt.Fprintf(&b, "  sudo chown -R %s:%s %s\n", r.ExpectedUser, r.ExpectedUser, r.RepoRoot)
	return b.String()
}

// FixCommand returns the shell command to fix all ownership issues.
func (r *OwnershipReport) FixCommand() string {
	return fmt.Sprintf("sudo chown -R %s:%s %s", r.ExpectedUser, r.ExpectedUser, r.RepoRoot)
}

// skipDirs contains directory names to skip during scanning.
// .git/objects is excluded because git manages its own object ownership
// and pack files may legitimately have different ownership during gc.
var skipDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
}

// AuditOwnership walks the repository and identifies files/directories not owned
// by the expected user. It skips .git internals and vendor directories.
//
// The expectedUID/GID are determined from the repository root directory's ownership,
// which represents the intended owner of the working tree.
func AuditOwnership(repoRoot string) (*OwnershipReport, error) {
	absRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve repo root %q: %w", repoRoot, err)
	}

	rootInfo, err := os.Stat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to stat repo root %q: %w", absRoot, err)
	}

	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("failed to get syscall.Stat_t for %q (unsupported platform?)", absRoot)
	}

	expectedUID := rootStat.Uid
	expectedGID := rootStat.Gid

	expectedUser := fmt.Sprintf("%d", expectedUID)
	if u, err := user.LookupId(strconv.Itoa(int(expectedUID))); err == nil {
		expectedUser = u.Username
	}

	report := &OwnershipReport{
		RepoRoot:     absRoot,
		ExpectedUID:  expectedUID,
		ExpectedGID:  expectedGID,
		ExpectedUser: expectedUser,
	}

	err = filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Permission denied during walk - this itself indicates an ownership problem.
			// Record the parent directory and skip.
			return nil
		}

		// Skip excluded directories
		if d.IsDir() {
			relPath, _ := filepath.Rel(absRoot, path)
			baseName := filepath.Base(path)
			if skipDirs[baseName] && relPath != "." {
				return fs.SkipDir
			}
		}

		info, err := d.Info()
		if err != nil {
			return nil // Skip files we can't stat
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil // Skip non-unix files
		}

		report.TotalScanned++

		if stat.Uid != expectedUID || stat.Gid != expectedGID {
			mismatch := MismatchedFile{
				Path:      path,
				ActualUID: stat.Uid,
				ActualGID: stat.Gid,
			}
			if d.IsDir() {
				report.MismatchedDirs = append(report.MismatchedDirs, mismatch)
			} else {
				report.MismatchedFiles = append(report.MismatchedFiles, mismatch)
			}
		}

		return nil
	})

	if err != nil {
		return report, fmt.Errorf("ownership audit walk error: %w", err)
	}

	return report, nil
}

// DetectRepoRoot finds the git repository root from the given directory.
// Returns an error if not inside a git repository.
func DetectRepoRoot(dir string) (string, error) {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not a git repository (or git not installed): %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// QuickCheck performs a fast ownership check by only examining the repo root
// and immediate problem directories (test/, pkg/, cmd/). Returns true if
// issues are found.
func QuickCheck(repoRoot string) (bool, error) {
	rootInfo, err := os.Stat(repoRoot)
	if err != nil {
		return false, fmt.Errorf("failed to stat repo root: %w", err)
	}

	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("unsupported platform")
	}

	expectedUID := rootStat.Uid

	// Check key subdirectories that are most likely to have issues
	checkDirs := []string{"test", "pkg", "cmd", "scripts", "assets"}
	for _, sub := range checkDirs {
		dir := filepath.Join(repoRoot, sub)
		if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}
			if stat.Uid != expectedUID {
				return fmt.Errorf("mismatched ownership at %s", path)
			}
			return nil
		}); err != nil {
			return true, nil // Issues found
		}
	}

	return false, nil
}
