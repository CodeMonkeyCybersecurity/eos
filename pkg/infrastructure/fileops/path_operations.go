package fileops

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/fileops"
)

// PathOperationsImpl implements PathOperations interface
type PathOperationsImpl struct{}

// NewPathOperations creates a new path operations implementation
func NewPathOperations() fileops.PathOperations {
	return &PathOperationsImpl{}
}

// JoinPath joins path elements
func (p *PathOperationsImpl) JoinPath(elem ...string) string {
	return filepath.Join(elem...)
}

// CleanPath returns the cleaned path
func (p *PathOperationsImpl) CleanPath(path string) string {
	return filepath.Clean(path)
}

// BaseName returns the base name of a path
func (p *PathOperationsImpl) BaseName(path string) string {
	return filepath.Base(path)
}

// DirName returns the directory of a path
func (p *PathOperationsImpl) DirName(path string) string {
	return filepath.Dir(path)
}

// IsAbsPath checks if a path is absolute
func (p *PathOperationsImpl) IsAbsPath(path string) bool {
	return filepath.IsAbs(path)
}

// RelPath returns a relative path
func (p *PathOperationsImpl) RelPath(basepath, targpath string) (string, error) {
	return filepath.Rel(basepath, targpath)
}

// ExpandPath expands environment variables and ~ in paths
func (p *PathOperationsImpl) ExpandPath(path string) string {
	// Expand ~ to home directory
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[2:])
		}
	}

	// Expand environment variables
	path = os.ExpandEnv(path)

	return path
}

// UpdateFilesInDir recursively scans the specified directory and replaces any occurrence
// of the provided token with the replacement value. This helper function can be moved to a
// common utils package if desired.
func UpdateFilesInDir(dir, token, replacement string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip directories
		if info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		contents := string(data)
		if strings.Contains(contents, token) {
			newContents := strings.ReplaceAll(contents, token, replacement)
			if err := os.WriteFile(path, []byte(newContents), info.Mode()); err != nil {
				return err
			}
			fmt.Printf("Updated file: %s\n", path)
		}
		return nil
	})
}
