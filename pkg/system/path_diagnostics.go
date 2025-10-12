// pkg/system/path_diagnostics.go
package system

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PathDiagnostics provides system PATH debugging capabilities
type PathDiagnostics struct {
	rc     *eos_io.RuntimeContext
	logger otelzap.LoggerWithCtx
}

// PathInfo contains information about system PATH configuration
type PathInfo struct {
	CurrentPath      string
	LoginShellPath   string
	PathSources      map[string][]string
	DuplicateEntries []string
	SnapStatus       string
	ConfigFiles      map[string]string
}

// NewPathDiagnostics creates a new PATH diagnostics instance
func NewPathDiagnostics(rc *eos_io.RuntimeContext) *PathDiagnostics {
	return &PathDiagnostics{
		rc:     rc,
		logger: otelzap.Ctx(rc.Ctx),
	}
}

// AnalyzePath performs comprehensive PATH analysis
func (pd *PathDiagnostics) AnalyzePath() (*PathInfo, error) {
	ctx, span := telemetry.Start(pd.rc.Ctx, "system.AnalyzePath")
	defer span.End()

	info := &PathInfo{
		PathSources: make(map[string][]string),
		ConfigFiles: make(map[string]string),
	}

	// Get current PATH
	info.CurrentPath = os.Getenv("PATH")
	pd.logger.Debug("Current PATH analyzed", zap.String("path", info.CurrentPath))

	// Get login shell PATH
	if err := pd.getLoginShellPath(ctx, info); err != nil {
		pd.logger.Warn("Failed to get login shell PATH", zap.Error(err))
	}

	// Analyze PATH sources
	if err := pd.analyzePathSources(ctx, info); err != nil {
		pd.logger.Warn("Failed to analyze PATH sources", zap.Error(err))
	}

	// Check for duplicates
	pd.findDuplicates(info)

	// Check snap status
	if err := pd.checkSnapStatus(ctx, info); err != nil {
		pd.logger.Warn("Failed to check snap status", zap.Error(err))
	}

	// Read configuration files
	if err := pd.readConfigFiles(ctx, info); err != nil {
		pd.logger.Warn("Failed to read config files", zap.Error(err))
	}

	return info, nil
}

// getLoginShellPath retrieves PATH from login shell
func (pd *PathDiagnostics) getLoginShellPath(ctx context.Context, info *PathInfo) error {
	cmd := exec.CommandContext(ctx, "bash", "--login", "-c", "echo $PATH")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get login shell PATH: %w", err)
	}

	info.LoginShellPath = strings.TrimSpace(string(output))
	return nil
}

// analyzePathSources finds where PATH is modified
func (pd *PathDiagnostics) analyzePathSources(ctx context.Context, info *PathInfo) error {
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	pathFiles := []string{
		filepath.Join(currentUser.HomeDir, ".bashrc"),
		filepath.Join(currentUser.HomeDir, ".profile"),
		filepath.Join(currentUser.HomeDir, ".bash_aliases"),
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/environment",
	}

	// Add profile.d files
	profileDFiles, _ := filepath.Glob("/etc/profile.d/*")
	pathFiles = append(pathFiles, profileDFiles...)

	// Search for PATH modifications in each file
	for _, file := range pathFiles {
		matches, err := pd.searchPathInFile(ctx, file)
		if err != nil {
			continue
		}
		if len(matches) > 0 {
			info.PathSources[file] = matches
		}
	}

	return nil
}

// searchPathInFile searches for PATH references in a file
func (pd *PathDiagnostics) searchPathInFile(ctx context.Context, filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var matches []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.Contains(strings.ToLower(line), "path") {
			matches = append(matches, fmt.Sprintf("Line %d: %s", lineNum, line))
		}
	}

	return matches, scanner.Err()
}

// findDuplicates identifies duplicate PATH entries
func (pd *PathDiagnostics) findDuplicates(info *PathInfo) {
	entries := strings.Split(info.CurrentPath, ":")
	seen := make(map[string]bool)

	for _, entry := range entries {
		if seen[entry] {
			info.DuplicateEntries = append(info.DuplicateEntries, entry)
		}
		seen[entry] = true
	}
}

// checkSnapStatus checks if snapd is running
func (pd *PathDiagnostics) checkSnapStatus(ctx context.Context, info *PathInfo) error {
	cmd := exec.CommandContext(ctx, "systemctl", "status", "snapd")
	err := cmd.Run()

	if err != nil {
		// Check if it's just inactive vs error
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 3 {
			info.SnapStatus = "inactive"
			return nil
		}
		info.SnapStatus = "error"
		return err
	}

	info.SnapStatus = "active"
	return nil
}

// readConfigFiles reads PATH-related configuration files
func (pd *PathDiagnostics) readConfigFiles(ctx context.Context, info *PathInfo) error {
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	configFiles := []string{
		"/etc/environment",
		filepath.Join(currentUser.HomeDir, ".bashrc"),
		filepath.Join(currentUser.HomeDir, ".profile"),
		"/etc/profile.d/apps-bin-path.sh",
	}

	for _, file := range configFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			pd.logger.Debug("Failed to read config file",
				zap.String("file", file),
				zap.Error(err))
			continue
		}

		info.ConfigFiles[file] = string(content)
	}

	return nil
}

// ApplyPathChanges reloads PATH configuration without reboot
func (pd *PathDiagnostics) ApplyPathChanges() error {
	ctx, span := telemetry.Start(pd.rc.Ctx, "system.ApplyPathChanges")
	defer span.End()

	pd.logger.Info("Applying PATH changes")

	// Note: In Go, we can't modify the parent shell's environment
	// This would typically be handled by outputting commands for the user
	return eos_err.NewExpectedError(ctx,
		fmt.Errorf("PATH changes must be applied in the shell using 'source' commands"))
}

// GenerateReport creates a human-readable PATH diagnostic report
func (pd *PathDiagnostics) GenerateReport(info *PathInfo) string {
	var report strings.Builder

	report.WriteString("=== PATH Diagnostics Report ===\n\n")

	report.WriteString("Current PATH:\n")
	for i, entry := range strings.Split(info.CurrentPath, ":") {
		report.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, entry))
	}

	if info.LoginShellPath != info.CurrentPath {
		report.WriteString("\nLogin Shell PATH (differs from current):\n")
		report.WriteString(fmt.Sprintf("  %s\n", info.LoginShellPath))
	}

	if len(info.DuplicateEntries) > 0 {
		report.WriteString("\nDuplicate PATH entries found:\n")
		for _, dup := range info.DuplicateEntries {
			report.WriteString(fmt.Sprintf("  - %s\n", dup))
		}
	}

	report.WriteString(fmt.Sprintf("\nSnap daemon status: %s\n", info.SnapStatus))

	if len(info.PathSources) > 0 {
		report.WriteString("\nPATH modifications found in:\n")
		for file, matches := range info.PathSources {
			report.WriteString(fmt.Sprintf("\n  %s:\n", file))
			for _, match := range matches {
				report.WriteString(fmt.Sprintf("    %s\n", match))
			}
		}
	}

	if len(info.ConfigFiles) > 0 {
		report.WriteString("\nConfiguration files content:\n")
		for file, content := range info.ConfigFiles {
			report.WriteString(fmt.Sprintf("\n  %s:\n", file))
			lines := strings.Split(content, "\n")
			for i, line := range lines {
				if i < 10 { // Show only first 10 lines
					report.WriteString(fmt.Sprintf("    %s\n", line))
				}
			}
			if len(lines) > 10 {
				report.WriteString("    ... (truncated)\n")
			}
		}
	}

	return report.String()
}
