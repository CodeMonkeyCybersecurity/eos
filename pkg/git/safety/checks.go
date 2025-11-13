// Package safety provides Git safety checks and validations
package safety

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunSafetyChecks performs comprehensive safety checks before committing.
// It follows the Assess → Intervene → Evaluate pattern.
func RunSafetyChecks(rc *eos_io.RuntimeContext, status *git.GitStatus) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check for conflicts
	if status.HasConflicts {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("cannot commit: there are unresolved merge conflicts"))
	}

	// Check if committing to protected branch
	protectedBranches := []string{"main", "master", "production", "prod"}
	for _, protected := range protectedBranches {
		if status.Branch == protected {
			logger.Warn("Committing to protected branch",
				zap.String("branch", status.Branch))
			break
		}
	}

	// INTERVENE - Run various checks
	allFiles := append(append(status.Staged, status.Modified...), status.Untracked...)
	if err := ScanForSecrets(rc, allFiles); err != nil {
		return err
	}

	if err := CheckFileSizes(rc, allFiles); err != nil {
		return err
	}

	if err := CheckForArtifacts(rc, allFiles); err != nil {
		return err
	}

	// EVALUATE
	logger.Debug("All safety checks passed")
	return nil
}

// ScanForSecrets scans files for potential secrets and sensitive information
func ScanForSecrets(rc *eos_io.RuntimeContext, files []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	secretPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['"]\w+['"]`),
		regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]\w+['"]`),
		regexp.MustCompile(`(?i)(secret|token)\s*[:=]\s*['"]\w+['"]`),
		regexp.MustCompile(`-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)aws_access_key_id`),
		regexp.MustCompile(`(?i)aws_secret_access_key`),
		regexp.MustCompile(`(?i)github_token`),
		regexp.MustCompile(`(?i)jwt_secret`),
		regexp.MustCompile(`(?i)database_url.*://.*:.*@`),
	}

	var suspiciousFiles []string

	for _, file := range files {
		// Skip binary files and directories
		if strings.HasSuffix(file, "/") {
			continue
		}

		// Check file extension
		ext := strings.ToLower(filepath.Ext(file))
		binaryExts := []string{".exe", ".dll", ".so", ".dylib", ".bin", ".img", ".iso"}
		for _, binExt := range binaryExts {
			if ext == binExt {
				continue
			}
		}

		// Read file content
		content, err := os.ReadFile(file)
		if err != nil {
			logger.Debug("Failed to read file for secret scanning",
				zap.String("file", file),
				zap.Error(err))
			continue
		}

		// Scan for patterns
		for _, pattern := range secretPatterns {
			if pattern.Match(content) {
				suspiciousFiles = append(suspiciousFiles, file)
				break
			}
		}
	}

	if len(suspiciousFiles) > 0 {
		logger.Warn("Potential secrets detected in files",
			zap.Strings("files", suspiciousFiles))
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("potential secrets detected in files: %v", suspiciousFiles))
	}

	return nil
}

// CheckFileSizes checks for files that are too large for Git
func CheckFileSizes(rc *eos_io.RuntimeContext, files []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	const maxFileSize = 50 * 1024 * 1024 // 50MB

	var largeFiles []string

	for _, file := range files {
		if strings.HasSuffix(file, "/") {
			continue
		}

		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		if info.Size() > maxFileSize {
			largeFiles = append(largeFiles, fmt.Sprintf("%s (%d MB)", file, info.Size()/(1024*1024)))
		}
	}

	if len(largeFiles) > 0 {
		logger.Warn("Large files detected", zap.Strings("files", largeFiles))
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("large files detected (>50MB): %v", largeFiles))
	}

	return nil
}

// CheckForArtifacts checks for build artifacts that shouldn't be committed
func CheckForArtifacts(rc *eos_io.RuntimeContext, files []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Platform-specific artifact patterns
	artifactPatterns := GetArtifactPatterns()

	var artifacts []string

	for _, file := range files {
		for _, pattern := range artifactPatterns {
			if matched, _ := filepath.Match(pattern, filepath.Base(file)); matched {
				artifacts = append(artifacts, file)
				break
			}
			if strings.Contains(file, strings.TrimSuffix(pattern, "/")) {
				artifacts = append(artifacts, file)
				break
			}
		}
	}

	if len(artifacts) > 0 {
		logger.Warn("Potential build artifacts detected", zap.Strings("files", artifacts))
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("potential artifacts detected: %v", artifacts))
	}

	return nil
}

// GetArtifactPatterns returns platform-specific patterns for build artifacts
func GetArtifactPatterns() []string {
	common := []string{
		"*.log", "*.tmp", "*.swp", "*.swo", "*~",
		"node_modules/", "vendor/", ".vscode/", ".idea/",
		"coverage.out", "*.test",
	}

	// Add platform-specific patterns
	if platform.IsMacOS() {
		common = append(common, ".DS_Store", "*.dSYM")
	}

	if platform.IsWindows() {
		common = append(common, "Thumbs.db", "*.exe", "*.dll", "*.pdb")
	}

	if platform.IsLinux() {
		common = append(common, "*.so", "*.a", "core.*")
	}

	// Add common binary extensions
	common = append(common, "*.o", "*.obj", "*.lib")

	return common
}
