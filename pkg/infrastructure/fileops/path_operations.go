package fileops

import (
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
