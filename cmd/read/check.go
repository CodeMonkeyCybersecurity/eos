package read

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check eos installation and environment",
	Long: `Check the eos installation, permissions, and environment configuration.

This command performs comprehensive diagnostics to help troubleshoot
common issues with eos installation and execution.

Examples:
  eos read check                   # Full system check
  eos read check --verbose         # Detailed diagnostic output`,
	RunE: eos.Wrap(runCheck),
}

func init() {
	ReadCmd.AddCommand(checkCmd)

	checkCmd.Flags().Bool("verbose", false, "Show detailed diagnostic information")
	checkCmd.Flags().Bool("fix", false, "Attempt to fix common issues (requires appropriate permissions)")
}

func runCheck(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	verbose, _ := cmd.Flags().GetBool("verbose")
	fix, _ := cmd.Flags().GetBool("fix")

	logger.Info("terminal prompt:  Eos Installation Check")
	logger.Info("terminal prompt: ========================")
	logger.Info("terminal prompt: ")

	// Track issues found
	var issues []string
	var warnings []string

	// 1. Check executable location and permissions
	logger.Info("terminal prompt: 📍 Checking executable location...")
	execPath, err := os.Executable()
	if err != nil {
		issues = append(issues, "Cannot determine executable path")
		logger.Error("Failed to get executable path", zap.Error(err))
	} else {
		logger.Info("terminal prompt:    Executable: " + execPath)

		// Check permissions
		if info, err := os.Stat(execPath); err == nil {
			mode := info.Mode()
			if verbose {
				logger.Info("terminal prompt:   📋 Permissions: " + mode.String())
			}

			if mode&0111 == 0 {
				issues = append(issues, "Executable is not executable")
				logger.Info("terminal prompt:   ❌ File is not executable")

				if fix {
					logger.Info("terminal prompt:    Attempting to fix permissions...")
					if err := os.Chmod(execPath, mode|0111); err != nil {
						logger.Info("terminal prompt:   ❌ Fix failed: " + err.Error())
					} else {
						logger.Info("terminal prompt:    Permissions fixed")
					}
				} else {
					logger.Info("terminal prompt:   💡 Run with --fix to attempt repair")
				}
			} else {
				logger.Info("terminal prompt:    Executable permissions OK")
			}
		}
	}

	// 2. Check if eos is in PATH
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: 🛣️  Checking PATH...")
	if pathEos, err := exec.LookPath("eos"); err == nil {
		logger.Info("terminal prompt:    Found in PATH: " + pathEos)
		if verbose && pathEos != execPath {
			logger.Info("terminal prompt:   Note: Different from current executable")
		}
	} else {
		warnings = append(warnings, "eos not found in PATH")
		logger.Info("terminal prompt:   Not found in PATH")
		if verbose {
			logger.Info("terminal prompt:   💡 Consider adding to PATH or installing system-wide")
		}
	}

	// 3. Check working directory
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt:  Checking working directory...")
	if wd, err := os.Getwd(); err == nil {
		logger.Info("terminal prompt:    Working directory: " + wd)

		// Check if local eos binary exists
		localEos := filepath.Join(wd, "eos")
		if info, err := os.Stat(localEos); err == nil && !info.IsDir() {
			if info.Mode()&0111 == 0 {
				warnings = append(warnings, "Local eos binary exists but is not executable")
				logger.Info("terminal prompt:   Local eos binary found but not executable")
			} else {
				logger.Info("terminal prompt:    Local eos binary found and executable")
			}
		}
	}

	// 4. Check user context
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt:  Checking user context...")
	logger.Info(fmt.Sprintf("terminal prompt:    User: %s (UID: %d, GID: %d)",
		func() string {
			if user := os.Getenv("USER"); user != "" {
				return user
			}
			if user := os.Getenv("USERNAME"); user != "" {
				return user
			}
			return "unknown"
		}(), os.Getuid(), os.Getgid()))

	if os.Geteuid() == 0 {
		logger.Info("terminal prompt:   🔐 Running as root")
	} else {
		logger.Info("terminal prompt:    Running as regular user")
	}

	// 5. Check system information
	if verbose {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: 💻 System information...")
		logger.Info("terminal prompt:   OS: " + runtime.GOOS)
		logger.Info("terminal prompt:   Architecture: " + runtime.GOARCH)
		logger.Info("terminal prompt:   Go version: " + runtime.Version())
	}

	// 6. Check common installation locations
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt:  Checking common installation locations...")
	commonPaths := []string{
		"/usr/local/bin/eos",
		"/usr/bin/eos",
		"/opt/eos/eos",
	}

	for _, path := range commonPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			if info.Mode()&0111 != 0 {
				logger.Info("terminal prompt:    Found: " + path)
			} else {
				logger.Info("terminal prompt:   Found but not executable: " + path)
			}
		} else if verbose {
			logger.Info("terminal prompt:   ❌ Not found: " + path)
		}
	}

	// 7. Check dependencies (if verbose)
	if verbose {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt:  Checking dependencies...")
		deps := []string{"git", "systemctl", "curl", "which"}
		for _, dep := range deps {
			if _, err := exec.LookPath(dep); err == nil {
				logger.Info("terminal prompt:    " + dep)
			} else {
				logger.Info("terminal prompt:   ❌ " + dep + " (not required)")
			}
		}
	}

	// Summary
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: 📊 Summary")
	logger.Info("terminal prompt: =======")

	if len(issues) == 0 && len(warnings) == 0 {
		logger.Info("terminal prompt:  All checks passed!")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Your eos installation appears to be working correctly.")

		// Show helpful usage information
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: 🚀 Quick Start:")
		logger.Info("terminal prompt:   eos create vault     # Install HashiCorp Vault")
		logger.Info("terminal prompt:   eos read status      # Check system status")
		logger.Info("terminal prompt:   eos --help           # Show all commands")

	} else {
		if len(issues) > 0 {
			logger.Info("terminal prompt: ❌ Issues found:")
			for _, issue := range issues {
				logger.Info("terminal prompt:   • " + issue)
			}
		}

		if len(warnings) > 0 {
			logger.Info("terminal prompt: Warnings:")
			for _, warning := range warnings {
				logger.Info("terminal prompt:   • " + warning)
			}
		}

		// Provide solutions
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt:  Suggested fixes:")

		if len(issues) > 0 {
			if strings.Contains(strings.Join(issues, " "), "not executable") {
				logger.Info("terminal prompt:   • Fix permissions: chmod +x ./eos")
				logger.Info("terminal prompt:   • Or run: eos read check --fix")
			}
		}

		if len(warnings) > 0 {
			if strings.Contains(strings.Join(warnings, " "), "PATH") {
				logger.Info("terminal prompt:   • Install system-wide: sudo cp eos /usr/local/bin/")
				logger.Info("terminal prompt:   • Or add to PATH: export PATH=$PATH:$(pwd)")
			}
		}
	}

	logger.Info("terminal prompt: ")
	return nil
}
