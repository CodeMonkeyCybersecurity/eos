// pkg/iris/temporal.go

package iris

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckPrerequisites verifies that required tools are available
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Check for Go and Temporal CLI
// - Intervene: N/A (read-only check)
// - Evaluate: Report findings and return error if Go is missing
func CheckPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Checking prerequisites for Iris installation")

	// Check Go
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("Go is not installed - please install Go 1.21+")
	}
	goVersion := exec.CommandContext(rc.Ctx, "go", "version")
	if output, err := goVersion.CombinedOutput(); err == nil {
		logger.Info("Go found", zap.String("version", string(output)))
	}

	// Check if Temporal CLI is available (optional - we'll install if missing)
	if _, err := exec.LookPath("temporal"); err != nil {
		logger.Warn("Temporal CLI not found - will be installed")
	} else {
		logger.Info("Temporal CLI found")
	}

	return nil
}

// InstallTemporal ensures Temporal CLI is installed and accessible
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Check if Temporal is already installed in PATH or common locations
// - Intervene: Download and install if not found
// - Evaluate: Verify installation succeeded and fix PATH if needed
func InstallTemporal(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Step 1: Check if Temporal is already accessible
	logger.Info("Checking if Temporal CLI is installed...")
	if temporalPath, err := exec.LookPath("temporal"); err == nil {
		// Verify it actually works
		versionCmd := exec.CommandContext(rc.Ctx, temporalPath, "--version")
		if output, err := versionCmd.CombinedOutput(); err == nil {
			version := strings.TrimSpace(string(output))
			logger.Info("Temporal CLI already installed and working",
				zap.String("path", temporalPath),
				zap.String("version", version))
			return nil
		}
		logger.Warn("Temporal found in PATH but not working", zap.String("path", temporalPath))
	}

	// ASSESS - Step 2: Check common installation locations (might be installed but not in PATH)
	logger.Info("Checking common Temporal installation locations...")
	commonPaths := []string{
		"/usr/local/bin/temporal",
		"/usr/bin/temporal",
		os.ExpandEnv("$HOME/.local/bin/temporal"),
		os.ExpandEnv("$HOME/.temporalio/bin/temporal"),
		"/root/.temporalio/bin/temporal",
	}

	for _, path := range commonPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			// Found it! Verify it works
			versionCmd := exec.CommandContext(rc.Ctx, path, "--version")
			if output, err := versionCmd.CombinedOutput(); err == nil {
				version := strings.TrimSpace(string(output))
				logger.Info("Found working Temporal CLI (not in PATH)",
					zap.String("path", path),
					zap.String("version", version))

				// Fix PATH issue by symlinking
				return FixTemporalPath(rc, path)
			}
		}
	}

	// INTERVENE - Step 3: Need to install - detect OS and architecture
	logger.Info("Temporal CLI not found, will install")
	goOS, goArch := DetectOSAndArch()
	logger.Info("Detected system architecture",
		zap.String("os", goOS),
		zap.String("arch", goArch))

	// INTERVENE - Step 4: Download and install using official installer
	logger.Info("Downloading Temporal CLI installer...")
	logger.Info("This may take a minute for the ~40MB download")

	// Use the official install script with explicit error handling
	installCmd := exec.CommandContext(rc.Ctx, "sh", "-c",
		"curl -sSf https://temporal.download/cli.sh | sh")

	// Capture output for debugging
	output, err := installCmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if err != nil {
		logger.Error("Temporal CLI installation failed",
			zap.Error(err),
			zap.String("output", outputStr))

		// Provide actionable error message
		return fmt.Errorf(`Temporal CLI installation failed

Problem: Installation script returned error
Output: %s
Error: %w

This could mean:
1. No internet connection or firewall blocking https://temporal.download
2. Installation script has changed or is temporarily unavailable
3. Insufficient disk space in download directory
4. Permissions issue writing to installation directory

To fix:
1. Check internet: curl -I https://temporal.download/cli.sh
2. Try manual install:
   curl -sSf https://temporal.download/cli.sh | sh
3. Or download from GitHub releases:
   https://github.com/temporalio/cli/releases
4. Ensure /usr/local/bin is writable or use sudo

After manual install, verify with: temporal --version`,
			outputStr, err)
	}

	// Log installation output for diagnostics
	if outputStr != "" {
		logger.Debug("Installation output", zap.String("output", outputStr))
	}

	// EVALUATE - Step 5: CRITICAL - Verify installation succeeded
	logger.Info("Verifying Temporal CLI installation...")

	// Check all possible locations again
	var workingPath string
	var version string

	// First try PATH
	if temporalPath, err := exec.LookPath("temporal"); err == nil {
		versionCmd := exec.CommandContext(rc.Ctx, temporalPath, "--version")
		if output, err := versionCmd.CombinedOutput(); err == nil {
			workingPath = temporalPath
			version = strings.TrimSpace(string(output))
		}
	}

	// If not in PATH, check common locations
	if workingPath == "" {
		for _, path := range commonPaths {
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				versionCmd := exec.CommandContext(rc.Ctx, path, "--version")
				if output, err := versionCmd.CombinedOutput(); err == nil {
					workingPath = path
					version = strings.TrimSpace(string(output))
					break
				}
			}
		}
	}

	if workingPath == "" {
		return fmt.Errorf(`Temporal CLI installation verification failed

Problem: Installation script completed but 'temporal' command not found

Checked locations:
- All directories in PATH: %s
- Common locations: /usr/local/bin, /usr/bin, ~/.local/bin, ~/.temporalio/bin

This usually means:
1. Installation script succeeded but installed to unexpected location
2. Installation directory is not in PATH
3. Installation script failed silently

To debug:
1. Search for temporal binary: sudo find / -name temporal -type f 2>/dev/null
2. Check installation logs above for clues
3. Try manual installation: https://docs.temporal.io/cli

If you find the binary, add its directory to PATH:
  export PATH="/path/to/temporal/dir:$PATH"
  echo 'export PATH="/path/to/temporal/dir:$PATH"' >> ~/.bashrc`,
			os.Getenv("PATH"))
	}

	// EVALUATE - Step 6: Binary found - check if it needs PATH fixing
	logger.Info("Temporal CLI installed successfully",
		zap.String("path", workingPath),
		zap.String("version", version))

	// If not in PATH, fix it
	if _, err := exec.LookPath("temporal"); err != nil {
		logger.Warn("Temporal installed but not in PATH, fixing...")
		return FixTemporalPath(rc, workingPath)
	}

	logger.Info("Temporal CLI is ready to use")
	return nil
}

// FixTemporalPath makes Temporal CLI accessible by copying it to /usr/local/bin
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Verify /usr/local/bin is in PATH and check if target exists
// - Intervene: Copy binary to /usr/local/bin
// - Evaluate: Verify the temporal command now works
func FixTemporalPath(rc *eos_io.RuntimeContext, temporalPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Fixing Temporal PATH accessibility",
		zap.String("source_path", temporalPath))

	// We copy the binary instead of symlinking, so no permission fixes needed on source
	// This keeps /root/ secure with its default 0700 permissions

	// ASSESS - Check if /usr/local/bin is in PATH
	pathEnv := os.Getenv("PATH")
	hasUsrLocalBin := false
	for _, dir := range strings.Split(pathEnv, ":") {
		if dir == "/usr/local/bin" {
			hasUsrLocalBin = true
			break
		}
	}

	if !hasUsrLocalBin {
		return fmt.Errorf(`Temporal CLI found at %s but /usr/local/bin not in PATH

Cannot create symlink because /usr/local/bin is not in your PATH.

Your PATH: %s

Fix Option 1 (Recommended): Add binary directory to PATH
  echo 'export PATH="%s:$PATH"' >> ~/.bashrc
  source ~/.bashrc

Fix Option 2: Add /usr/local/bin to PATH
  echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc
  source ~/.bashrc
  Then re-run: eos create iris`,
			temporalPath, pathEnv, filepath.Dir(temporalPath))
	}

	// INTERVENE - Copy binary to /usr/local/bin instead of symlinking
	// Reason: If source is in /root/, symlink won't work for non-root users
	targetPath := "/usr/local/bin/temporal"

	// Check if target already exists and works
	if info, err := os.Stat(targetPath); err == nil {
		versionCmd := exec.CommandContext(rc.Ctx, targetPath, "--version")
		if versionCmd.Run() == nil {
			logger.Info("Temporal already installed in /usr/local/bin",
				zap.String("path", targetPath),
				zap.Int64("size", info.Size()))
			return nil
		}
		// Exists but doesn't work - remove and replace
		logger.Info("Existing temporal binary doesn't work, replacing")
		_ = os.Remove(targetPath)
	}

	// Copy the binary to /usr/local/bin
	logger.Info("Copying temporal binary to /usr/local/bin",
		zap.String("from", temporalPath),
		zap.String("to", targetPath))

	sourceData, err := os.ReadFile(temporalPath)
	if err != nil {
		return fmt.Errorf("failed to read source binary: %w", err)
	}

	// Write with executable permissions
	if err := os.WriteFile(targetPath, sourceData, shared.ExecutablePerm); err != nil {
		return fmt.Errorf("failed to write binary to %s: %w", targetPath, err)
	}

	logger.Info("Binary copied successfully",
		zap.String("path", targetPath),
		zap.Int("size_bytes", len(sourceData)))

	// EVALUATE - Verify it works
	versionCmd := exec.CommandContext(rc.Ctx, "temporal", "--version")
	if output, err := versionCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("binary copied but temporal command still not working: %w\nOutput: %s", err, string(output))
	}

	logger.Info("Temporal CLI is now available system-wide")
	return nil
}

// DetectOSAndArch detects the operating system and architecture
func DetectOSAndArch() (string, string) {
	// Use Go's runtime to detect OS and arch
	// This matches what Temporal's install script does
	goOS := os.Getenv("GOOS")
	if goOS == "" {
		goOS = "linux" // Default assumption for eos
	}

	goArch := os.Getenv("GOARCH")
	if goArch == "" {
		// Try to detect from `uname -m`
		if unameCmd := exec.Command("uname", "-m"); true {
			if output, err := unameCmd.Output(); err == nil {
				machine := strings.TrimSpace(string(output))
				switch machine {
				case "x86_64", "amd64":
					goArch = "amd64"
				case "aarch64", "arm64":
					goArch = "arm64"
				case "armv7l":
					goArch = "arm"
				default:
					goArch = "amd64" // Default
				}
			}
		}
	}

	return goOS, goArch
}
