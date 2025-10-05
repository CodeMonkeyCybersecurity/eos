// Package git provides Git repository management utilities
package git

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// EnsureInProjectRoot ensures we are in the Eos project root directory.
// It follows the Assess → Intervene → Evaluate pattern.
func EnsureInProjectRoot(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Get current directory
	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Look for go.mod in current dir or walk up the tree
	projectRoot, err := FindProjectRoot(currentDir)
	if err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("not in Eos project: %v", err))
	}

	// INTERVENE - Change to project root if not already there
	if projectRoot != currentDir {
		logger.Info("Changing to project root", zap.String("from", currentDir), zap.String("to", projectRoot))
		if err := os.Chdir(projectRoot); err != nil {
			return fmt.Errorf("failed to change to project root: %w", err)
		}
	}

	// EVALUATE - Verify we're in the correct directory
	logger.Debug("Verified in Eos project root", zap.String("path", projectRoot))
	return nil
}

// FindProjectRoot finds the Eos project root directory by looking for go.mod.
// It walks up the directory tree until it finds a go.mod file with the Eos module.
func FindProjectRoot(startDir string) (string, error) {
	dir := startDir

	for {
		// Check for go.mod with Eos module
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			content, err := os.ReadFile(goModPath)
			if err == nil && strings.Contains(string(content), "module github.com/CodeMonkeyCybersecurity/eos") {
				return dir, nil
			}
		}

		// Move up one directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("EOS project root not found (no go.mod with Eos module)")
}
