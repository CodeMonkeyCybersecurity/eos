// pkg/security_permissions/permissions.go
package security_permissions

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckPermissions checks permissions for specified categories following Assess → Intervene → Evaluate pattern
func CheckPermissions(rc *eos_io.RuntimeContext, config *SecurityConfig, categories []string) (*PermissionFixResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	if config == nil {
		config = DefaultSecurityConfig()
	}
	
	logger.Info("Assessing permission check requirements",
		zap.Strings("categories", categories),
		zap.Bool("dry_run", true))

	result := &PermissionFixResult{
		Timestamp:  time.Now(),
		DryRun:     true, // Check is always dry-run
		Categories: categories,
		Results:    make(map[string]PermissionScanResult),
		Summary: PermissionSummary{
			Errors: make([]string, 0),
		},
	}

	// INTERVENE
	logger.Info("Checking permissions", zap.Strings("categories", categories))

	// Process each category
	for _, category := range categories {
		scanResult, err := checkCategoryPermissions(rc, config, category)
		if err != nil {
			result.Summary.Errors = append(result.Summary.Errors,
				fmt.Sprintf("Error checking %s: %v", category, err))
			continue
		}

		result.Results[category] = *scanResult
		result.Summary.TotalFiles += scanResult.TotalChecks
		result.Summary.FilesSkipped += scanResult.Passed
	}

	// Calculate files that would need fixing
	for _, scanResult := range result.Results {
		for _, check := range scanResult.Checks {
			if check.NeedsChange {
				result.Summary.FilesFixed++
			}
		}
	}

	// EVALUATE
	result.Summary.Success = len(result.Summary.Errors) == 0
	
	logger.Info("Permission check completed successfully",
		zap.Int("total_files", result.Summary.TotalFiles),
		zap.Int("files_need_fixing", result.Summary.FilesFixed),
		zap.Bool("success", result.Summary.Success))

	return result, nil
}

// FixPermissions fixes permissions for specified categories following Assess → Intervene → Evaluate pattern
func FixPermissions(rc *eos_io.RuntimeContext, config *SecurityConfig, categories []string) (*PermissionFixResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	if config == nil {
		config = DefaultSecurityConfig()
	}
	
	logger.Info("Assessing permission fix requirements",
		zap.Strings("categories", categories),
		zap.Bool("dry_run", config.DryRun))

	result := &PermissionFixResult{
		Timestamp:  time.Now(),
		DryRun:     config.DryRun,
		Categories: categories,
		Results:    make(map[string]PermissionScanResult),
		Summary: PermissionSummary{
			Errors: make([]string, 0),
		},
	}

	// INTERVENE
	if config.DryRun {
		logger.Info("Dry run: would fix permissions", zap.Strings("categories", categories))
	} else {
		logger.Info("Fixing permissions", zap.Strings("categories", categories))
	}

	// Process each category
	for _, category := range categories {
		scanResult, err := fixCategoryPermissions(rc, config, category)
		if err != nil {
			result.Summary.Errors = append(result.Summary.Errors,
				fmt.Sprintf("Error fixing %s: %v", category, err))
			continue
		}

		result.Results[category] = *scanResult
		result.Summary.TotalFiles += scanResult.TotalChecks
		result.Summary.FilesFixed += scanResult.Fixed
		result.Summary.FilesSkipped += scanResult.Passed
	}

	// EVALUATE
	result.Summary.Success = len(result.Summary.Errors) == 0
	
	logger.Info("Permission fix completed successfully",
		zap.Int("total_files", result.Summary.TotalFiles),
		zap.Int("files_fixed", result.Summary.FilesFixed),
		zap.Bool("success", result.Summary.Success))

	return result, nil
}

// ScanSSHDirectory scans SSH directory for permission issues following Assess → Intervene → Evaluate pattern
func ScanSSHDirectory(rc *eos_io.RuntimeContext, config *SecurityConfig, sshDir string) (*PermissionScanResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	if config == nil {
		config = DefaultSecurityConfig()
	}
	
	logger.Info("Assessing SSH directory scan", zap.String("ssh_dir", sshDir))

	result := &PermissionScanResult{
		Timestamp: time.Now(),
		Category:  "ssh",
		Checks:    make([]PermissionCheck, 0),
	}

	// INTERVENE
	logger.Info("Scanning SSH directory", zap.String("ssh_dir", sshDir))

	// Check if SSH directory exists
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		logger.Info("SSH directory does not exist, skipping scan")
		return result, nil
	}

	// Check SSH directory itself
	check := checkSinglePath(sshDir, 0700, "SSH directory", true)
	result.Checks = append(result.Checks, check)
	result.TotalChecks++

	if check.NeedsChange {
		result.Failed++
	} else if check.Error != "" {
		result.Errors++
	} else {
		result.Passed++
	}

	// Walk through SSH directory
	err := filepath.Walk(sshDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Skip the directory itself (already checked)
		if path == sshDir {
			return nil
		}

		// Skip excluded patterns
		if shouldExcludePath(config, path) {
			return nil
		}

		// Determine appropriate permissions
		var expectedMode os.FileMode
		var description string

		if info.IsDir() {
			expectedMode = 0700
			description = "SSH subdirectory"
		} else if IsPrivateKey(info.Name()) {
			expectedMode = 0600
			description = "SSH private key"
		} else if strings.HasSuffix(info.Name(), ".pub") {
			expectedMode = 0644
			description = "SSH public key"
		} else if info.Name() == "known_hosts" {
			expectedMode = 0644
			description = "SSH known hosts"
		} else {
			expectedMode = 0600
			description = "SSH configuration file"
		}

		check := checkSinglePath(path, expectedMode, description, false)
		result.Checks = append(result.Checks, check)
		result.TotalChecks++

		if check.NeedsChange {
			result.Failed++
		} else if check.Error != "" {
			result.Errors++
		} else {
			result.Passed++
		}

		return nil
	})

	// EVALUATE
	if err != nil {
		logger.Error("SSH directory scan failed", zap.Error(err))
		return result, fmt.Errorf("error walking SSH directory: %w", err)
	}

	logger.Info("SSH directory scan completed successfully",
		zap.String("ssh_dir", sshDir),
		zap.Int("total_checks", result.TotalChecks),
		zap.Int("passed", result.Passed),
		zap.Int("failed", result.Failed))

	return result, nil
}

// Helper functions

func checkCategoryPermissions(rc *eos_io.RuntimeContext, config *SecurityConfig, category string) (*PermissionScanResult, error) {
	result := &PermissionScanResult{
		Timestamp: time.Now(),
		Category:  category,
		Checks:    make([]PermissionCheck, 0),
	}

	// Handle special SSH directory scanning
	if category == "ssh" {
		return ScanSSHDirectory(rc, config, config.SSHDirectory)
	}

	// Get rules for this category
	rules := GetPermissionRules([]string{category})

	for _, rule := range rules {
		expandedPath := os.ExpandEnv(rule.Path)
		check := checkSinglePath(expandedPath, rule.Mode, rule.Description, rule.Required)
		result.Checks = append(result.Checks, check)
		result.TotalChecks++

		if check.NeedsChange {
			result.Failed++
		} else if check.Error != "" {
			result.Errors++
		} else {
			result.Passed++
		}
	}

	return result, nil
}

func fixCategoryPermissions(rc *eos_io.RuntimeContext, config *SecurityConfig, category string) (*PermissionScanResult, error) {
	result := &PermissionScanResult{
		Timestamp: time.Now(),
		Category:  category,
		Checks:    make([]PermissionCheck, 0),
	}

	// Handle special SSH directory scanning and fixing
	if category == "ssh" {
		return fixSSHDirectory(rc, config, config.SSHDirectory)
	}

	// Get rules for this category
	rules := GetPermissionRules([]string{category})

	for _, rule := range rules {
		expandedPath := os.ExpandEnv(rule.Path)
		check := fixSinglePath(config, expandedPath, rule.Mode, rule.Description, rule.Required)
		result.Checks = append(result.Checks, check)
		result.TotalChecks++

		if check.Error != "" {
			result.Errors++
		} else if check.NeedsChange && !config.DryRun {
			result.Fixed++
		} else {
			result.Passed++
		}
	}

	return result, nil
}

func fixSSHDirectory(rc *eos_io.RuntimeContext, config *SecurityConfig, sshDir string) (*PermissionScanResult, error) {
	result := &PermissionScanResult{
		Timestamp: time.Now(),
		Category:  "ssh",
		Checks:    make([]PermissionCheck, 0),
	}

	// Check if SSH directory exists
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		return result, nil // Skip if directory doesn't exist
	}

	// Fix SSH directory itself
	check := fixSinglePath(config, sshDir, 0700, "SSH directory", true)
	result.Checks = append(result.Checks, check)
	result.TotalChecks++

	if check.Error != "" {
		result.Errors++
	} else if check.NeedsChange && !config.DryRun {
		result.Fixed++
	} else {
		result.Passed++
	}

	// Walk through SSH directory
	err := filepath.Walk(sshDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Skip the directory itself (already checked)
		if path == sshDir {
			return nil
		}

		// Skip excluded patterns
		if shouldExcludePath(config, path) {
			return nil
		}

		// Determine appropriate permissions
		var expectedMode os.FileMode
		var description string

		if info.IsDir() {
			expectedMode = 0700
			description = "SSH subdirectory"
		} else if IsPrivateKey(info.Name()) {
			expectedMode = 0600
			description = "SSH private key"
		} else if strings.HasSuffix(info.Name(), ".pub") {
			expectedMode = 0644
			description = "SSH public key"
		} else if info.Name() == "known_hosts" {
			expectedMode = 0644
			description = "SSH known hosts"
		} else {
			expectedMode = 0600
			description = "SSH configuration file"
		}

		check := fixSinglePath(config, path, expectedMode, description, false)
		result.Checks = append(result.Checks, check)
		result.TotalChecks++

		if check.Error != "" {
			result.Errors++
		} else if check.NeedsChange && !config.DryRun {
			result.Fixed++
		} else {
			result.Passed++
		}

		return nil
	})

	if err != nil {
		return result, fmt.Errorf("error walking SSH directory: %w", err)
	}

	return result, nil
}

func checkSinglePath(path string, expectedMode os.FileMode, description string, required bool) PermissionCheck {
	check := PermissionCheck{
		Rule: PermissionRule{
			Path:        path,
			Mode:        expectedMode,
			Description: description,
			Required:    required,
		},
		ExpectedMode: expectedMode,
	}

	// Check if path exists
	stat, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			if required {
				check.Error = "Required path does not exist"
			} else {
				check.Error = "Path does not exist (optional)"
			}
		} else {
			check.Error = fmt.Sprintf("Cannot access path: %v", err)
		}
		return check
	}

	check.Exists = true
	check.CurrentMode = stat.Mode() & os.ModePerm
	check.NeedsChange = check.CurrentMode != expectedMode

	return check
}

func fixSinglePath(config *SecurityConfig, path string, expectedMode os.FileMode, description string, required bool) PermissionCheck {
	check := checkSinglePath(path, expectedMode, description, required)

	// If the path doesn't exist or there's an error, return as-is
	if !check.Exists || check.Error != "" {
		return check
	}

	// If permissions are correct, no change needed
	if !check.NeedsChange {
		return check
	}

	// Create backup if enabled
	if config.CreateBackups && !config.DryRun {
		if err := createBackup(config, path); err != nil {
			check.Error = fmt.Sprintf("Failed to create backup: %v", err)
			return check
		}
	}

	// Fix permissions (unless in dry-run mode)
	if !config.DryRun {
		if err := os.Chmod(path, expectedMode); err != nil {
			check.Error = fmt.Sprintf("Failed to change permissions: %v", err)
			return check
		}

		// Update the current mode to reflect the change
		check.CurrentMode = expectedMode
		check.NeedsChange = false
	}

	return check
}

func createBackup(config *SecurityConfig, path string) error {
	if config.BackupDirectory == "" {
		return nil // No backup directory specified
	}

	// Create backup directory if it doesn't exist
	if err := os.MkdirAll(config.BackupDirectory, shared.SecretDirPerm); err != nil {
		return err
	}

	// Create a simple record of the original permissions
	stat, err := os.Stat(path)
	if err != nil {
		return err
	}

	backupFile := filepath.Join(config.BackupDirectory,
		fmt.Sprintf("permissions_%d.log", time.Now().Unix()))

	backupData := fmt.Sprintf("%s: %o\n", path, stat.Mode()&os.ModePerm)

	return os.WriteFile(backupFile, []byte(backupData), shared.SecretFilePerm)
}

func shouldExcludePath(config *SecurityConfig, path string) bool {
	filename := filepath.Base(path)

	for _, pattern := range config.ExcludePatterns {
		if matched, _ := filepath.Match(pattern, filename); matched {
			return true
		}
	}

	return false
}