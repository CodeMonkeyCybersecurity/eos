package eos_cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckExecutablePermissions validates that the eos binary can be executed
// and provides helpful error messages if not
func CheckExecutablePermissions(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Get the path to the current executable
	execPath, err := os.Executable()
	if err != nil {
		logger.Error("Failed to determine executable path", zap.Error(err))
		return eos_err.NewUserError("Unable to determine eos executable path")
	}
	
	// Log the execution attempt for debugging
	logger.Info("Checking eos binary permissions",
		zap.String("executable_path", execPath),
		zap.Int("user_uid", os.Getuid()),
		zap.Int("user_gid", os.Getgid()))
	
	// Check if file exists
	if _, err := os.Stat(execPath); os.IsNotExist(err) {
		logger.Error("Eos executable not found",
			zap.String("path", execPath))
		
		return eos_err.NewUserError("Eos executable not found at: " + execPath + "\n\n" +
			"This usually means:\n" +
			"• The binary was moved or deleted\n" +
			"• You're running from the wrong directory\n" +
			"• The installation is corrupted\n\n" +
			"Try reinstalling eos or check the installation path.")
	}
	
	// Check file permissions
	info, err := os.Stat(execPath)
	if err != nil {
		logger.Error("Failed to check executable permissions",
			zap.String("path", execPath),
			zap.Error(err))
		return eos_err.NewUserError("Unable to check eos executable permissions")
	}
	
	mode := info.Mode()
	
	// Check if executable bit is set
	if mode&0111 == 0 {
		logger.Error("Eos binary is not executable",
			zap.String("path", execPath),
			zap.String("current_permissions", mode.String()))
		
		return eos_err.NewUserError("Eos binary is not executable: " + execPath + "\n" +
			"Current permissions: " + mode.String() + "\n\n" +
			"To fix this, run:\n" +
			"  chmod +x " + execPath + "\n\n" +
			"Or if you installed via package manager:\n" +
			"  sudo chmod +x /usr/local/bin/eos")
	}
	
	// Check ownership and suggest solutions
	if info.Sys() != nil {
		// Additional ownership checks could go here
		logger.Debug("Executable permissions verified",
			zap.String("path", execPath),
			zap.String("permissions", mode.String()))
	}
	
	return nil
}

// SuggestExecutionMethod provides helpful suggestions for running eos commands
func SuggestExecutionMethod(rc *eos_io.RuntimeContext, commandPath string) string {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Providing execution method suggestions",
		zap.String("attempted_path", commandPath))
	
	// Check if eos is in PATH
	if _, err := exec.LookPath("eos"); err == nil {
		return "eos is available in PATH. Try running: eos create vault"
	}
	
	// Check common installation locations
	commonPaths := []string{
		"/usr/local/bin/eos",
		"/usr/bin/eos",
		"/opt/eos/eos",
		filepath.Join(os.Getenv("HOME"), "bin/eos"),
	}
	
	for _, path := range commonPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			if info.Mode()&0111 != 0 {
				return fmt.Sprintf("Found eos at: %s\nTry running: %s create vault", path, path)
			}
		}
	}
	
	// Build current directory suggestion
	currentDir, _ := os.Getwd()
	localEos := filepath.Join(currentDir, "eos")
	
	if info, err := os.Stat(localEos); err == nil && !info.IsDir() {
		if info.Mode()&0111 == 0 {
			return fmt.Sprintf(
				"Found eos binary in current directory but it's not executable.\n"+
				"Run: chmod +x ./eos && ./eos create vault")
		}
		return "Try running: ./eos create vault"
	}
	
	return "Eos binary not found. Please check installation or run from correct directory."
}