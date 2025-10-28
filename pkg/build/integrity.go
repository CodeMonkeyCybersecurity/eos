// pkg/build/integrity.go
//
// Build integrity verification - security-critical code
// Verifies build environment hasn't been tampered with before compiling eos

package build

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BuildIntegrityCheck contains results of build environment verification
type BuildIntegrityCheck struct {
	GoCompilerVerified    bool     // Go compiler permissions and existence verified
	GoCompilerPath        string   // Path to go compiler
	SourceDirVerified     bool     // Source directory is not a symlink
	EnvironmentSanitized  bool     // Dangerous env vars removed
	GoModulesVerified     bool     // go.mod and go.sum exist
	Warnings              []string // Non-fatal warnings
}

// DangerousEnvironmentVars are environment variables that could be exploited
// to inject malicious code during build
var DangerousEnvironmentVars = []string{
	"LD_PRELOAD",      // Can inject malicious shared libraries
	"LD_LIBRARY_PATH", // Can redirect library loads to attacker-controlled paths
	"DYLD_INSERT_LIBRARIES",      // macOS equivalent of LD_PRELOAD
	"DYLD_LIBRARY_PATH",          // macOS equivalent of LD_LIBRARY_PATH
	"GOPATH",          // Could redirect go module cache to malicious code
	"GOCACHE",         // Could use poisoned build cache
}

// VerifyBuildIntegrity performs comprehensive build environment verification
// SECURITY CRITICAL: This prevents supply chain attacks via compromised build tools
func VerifyBuildIntegrity(rc *eos_io.RuntimeContext, goPath, sourceDir string) (*BuildIntegrityCheck, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying build environment integrity")

	check := &BuildIntegrityCheck{
		GoCompilerPath: goPath,
	}

	// Step 1: Verify Go compiler integrity
	if err := verifyGoCompilerIntegrity(rc, goPath, check); err != nil {
		return check, err
	}

	// Step 2: Verify source directory integrity
	if err := verifySourceDirectoryIntegrity(rc, sourceDir, check); err != nil {
		return check, err
	}

	// Step 3: Sanitize build environment
	if err := sanitizeBuildEnvironment(rc, check); err != nil {
		return check, err
	}

	// Step 4: Verify go.mod and go.sum exist
	if err := verifyGoModules(rc, sourceDir, check); err != nil {
		return check, err
	}

	logger.Info("Build environment integrity verified",
		zap.Bool("go_compiler_ok", check.GoCompilerVerified),
		zap.Bool("source_dir_ok", check.SourceDirVerified),
		zap.Bool("environment_ok", check.EnvironmentSanitized),
		zap.Bool("go_modules_ok", check.GoModulesVerified),
		zap.Int("warnings", len(check.Warnings)))

	return check, nil
}

// verifyGoCompilerIntegrity checks that the go compiler hasn't been tampered with
func verifyGoCompilerIntegrity(rc *eos_io.RuntimeContext, goPath string, check *BuildIntegrityCheck) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if go binary exists
	goInfo, err := os.Stat(goPath)
	if err != nil {
		return fmt.Errorf("go compiler not found at %s: %w", goPath, err)
	}

	// SECURITY CHECK: Verify go compiler is not world-writable
	// World-writable compiler could be replaced by any user with trojan
	if goInfo.Mode().Perm()&0002 != 0 {
		return fmt.Errorf("SECURITY VIOLATION: Go compiler is world-writable\n"+
			"Compiler: %s\n"+
			"Permissions: %s\n\n"+
			"DANGER: Any user can modify your go compiler!\n"+
			"This is a critical security vulnerability.\n\n"+
			"Fix:\n"+
			"  sudo chmod 755 %s",
			goPath, goInfo.Mode().String(), goPath)
	}

	// SECURITY CHECK: Verify go compiler is not group-writable (unless root group)
	if goInfo.Mode().Perm()&0020 != 0 {
		// Get file group
		stat, ok := goInfo.Sys().(*syscall.Stat_t)
		if ok && stat.Gid != 0 {  // If group is not root (GID 0)
			warning := fmt.Sprintf("Go compiler is group-writable (GID %d): %s", stat.Gid, goPath)
			check.Warnings = append(check.Warnings, warning)
			logger.Warn("SECURITY WARNING: Go compiler is group-writable",
				zap.String("path", goPath),
				zap.Uint32("gid", stat.Gid),
				zap.String("perms", goInfo.Mode().String()))
		}
	}

	// Verify go compiler works
	versionCmd := exec.Command(goPath, "version")
	versionOutput, err := versionCmd.Output()
	if err != nil {
		return fmt.Errorf("go compiler at %s is not functional: %w", goPath, err)
	}

	versionStr := strings.TrimSpace(string(versionOutput))
	logger.Debug("Go compiler verified",
		zap.String("path", goPath),
		zap.String("version", versionStr),
		zap.String("permissions", goInfo.Mode().String()))

	check.GoCompilerVerified = true
	return nil
}

// verifySourceDirectoryIntegrity checks that source directory hasn't been symlink-swapped
func verifySourceDirectoryIntegrity(rc *eos_io.RuntimeContext, sourceDir string, check *BuildIntegrityCheck) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Use Lstat (not Stat) to detect symlinks
	sourceDirInfo, err := os.Lstat(sourceDir)
	if err != nil {
		return fmt.Errorf("source directory not found: %s: %w", sourceDir, err)
	}

	// SECURITY CHECK: Source directory must not be a symlink
	// Attacker could swap symlink target mid-build to inject malicious code
	if sourceDirInfo.Mode()&os.ModeSymlink != 0 {
		target, _ := os.Readlink(sourceDir)
		return fmt.Errorf("SECURITY VIOLATION: Source directory is a symlink\n"+
			"Directory: %s\n"+
			"Target: %s\n\n"+
			"DANGER: Attacker could swap symlink target during build!\n\n"+
			"Fix:\n"+
			"  # Remove symlink and use real directory\n"+
			"  sudo rm %s\n"+
			"  # Clone eos directly\n"+
			"  sudo git clone https://github.com/CodeMonkeyCybersecurity/eos.git %s",
			sourceDir, target, sourceDir, sourceDir)
	}

	// Verify directory is actually a directory
	if !sourceDirInfo.IsDir() {
		return fmt.Errorf("source path is not a directory: %s", sourceDir)
	}

	logger.Debug("Source directory verified",
		zap.String("path", sourceDir),
		zap.String("permissions", sourceDirInfo.Mode().String()))

	check.SourceDirVerified = true
	return nil
}

// sanitizeBuildEnvironment removes dangerous environment variables
func sanitizeBuildEnvironment(rc *eos_io.RuntimeContext, check *BuildIntegrityCheck) error {
	logger := otelzap.Ctx(rc.Ctx)

	removedVars := []string{}

	for _, envVar := range DangerousEnvironmentVars {
		if val := os.Getenv(envVar); val != "" {
			logger.Warn("SECURITY: Removing dangerous environment variable before build",
				zap.String("variable", envVar),
				zap.String("value", val),
				zap.String("reason", "Could be exploited to inject malicious code"))

			os.Unsetenv(envVar)
			removedVars = append(removedVars, envVar)
		}
	}

	if len(removedVars) > 0 {
		warning := fmt.Sprintf("Removed %d dangerous environment variables: %v",
			len(removedVars), removedVars)
		check.Warnings = append(check.Warnings, warning)
		logger.Info("Build environment sanitized",
			zap.Strings("removed_vars", removedVars))
	}

	check.EnvironmentSanitized = true
	return nil
}

// verifyGoModules verifies go.mod and go.sum exist and are valid
func verifyGoModules(rc *eos_io.RuntimeContext, sourceDir string, check *BuildIntegrityCheck) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check go.mod exists
	goModPath := filepath.Join(sourceDir, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		return fmt.Errorf("go.mod not found in source directory: %s: %w", sourceDir, err)
	}

	// Check go.sum exists
	// go.sum is critical for reproducible builds and supply chain security
	goSumPath := filepath.Join(sourceDir, "go.sum")
	if _, err := os.Stat(goSumPath); err != nil {
		return fmt.Errorf("go.sum not found (required for secure builds): %s: %w\n\n"+
			"go.sum provides cryptographic checksums of dependencies.\n"+
			"Without it, dependency substitution attacks are possible.\n\n"+
			"Fix:\n"+
			"  cd %s\n"+
			"  go mod download\n"+
			"  go mod tidy",
			sourceDir, err, sourceDir)
	}

	logger.Debug("Go modules verified",
		zap.String("go_mod", goModPath),
		zap.String("go_sum", goSumPath))

	check.GoModulesVerified = true
	return nil
}
