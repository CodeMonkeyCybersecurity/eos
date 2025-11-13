package security_permissions

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PermissionManager handles security permission management
type PermissionManager struct {
	config *SecurityConfig
}

// NewPermissionManager creates a new permission manager
func NewPermissionManager(config *SecurityConfig) *PermissionManager {
	if config == nil {
		config = DefaultSecurityConfig()
	}

	return &PermissionManager{
		config: config,
	}
}

// CheckPermissions checks permissions for the specified categories
func (pm *PermissionManager) CheckPermissions(categories []string) (*PermissionFixResult, error) {
	result := &PermissionFixResult{
		Timestamp:  time.Now(),
		DryRun:     true, // Check is always dry-run
		Categories: categories,
		Results:    make(map[string]PermissionScanResult),
		Summary: PermissionSummary{
			Errors: make([]string, 0),
		},
	}

	// Process each category
	for _, category := range categories {
		scanResult, err := pm.checkCategoryPermissions(category)
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

	result.Summary.Success = len(result.Summary.Errors) == 0
	return result, nil
}

// FixPermissions fixes permissions for the specified categories
func (pm *PermissionManager) FixPermissions(categories []string) (*PermissionFixResult, error) {
	result := &PermissionFixResult{
		Timestamp:  time.Now(),
		DryRun:     pm.config.DryRun,
		Categories: categories,
		Results:    make(map[string]PermissionScanResult),
		Summary: PermissionSummary{
			Errors: make([]string, 0),
		},
	}

	// Process each category
	for _, category := range categories {
		scanResult, err := pm.fixCategoryPermissions(category)
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

	result.Summary.Success = len(result.Summary.Errors) == 0
	return result, nil
}

// ScanSSHDirectory scans SSH directory for permission issues
func (pm *PermissionManager) ScanSSHDirectory(sshDir string) (*PermissionScanResult, error) {
	result := &PermissionScanResult{
		Timestamp: time.Now(),
		Category:  "ssh",
		Checks:    make([]PermissionCheck, 0),
	}

	// Check if SSH directory exists
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		return result, nil // Skip if directory doesn't exist
	}

	// Check SSH directory itself
	check := pm.checkSinglePath(sshDir, 0700, "SSH directory", true)
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
		if pm.shouldExcludePath(path) {
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

		check := pm.checkSinglePath(path, expectedMode, description, false)
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

	if err != nil {
		return result, fmt.Errorf("error walking SSH directory: %v", err)
	}

	return result, nil
}

// checkCategoryPermissions checks permissions for a specific category
func (pm *PermissionManager) checkCategoryPermissions(category string) (*PermissionScanResult, error) {
	result := &PermissionScanResult{
		Timestamp: time.Now(),
		Category:  category,
		Checks:    make([]PermissionCheck, 0),
	}

	// Handle special SSH directory scanning
	if category == "ssh" {
		return pm.ScanSSHDirectory(pm.config.SSHDirectory)
	}

	// Get rules for this category
	rules := GetPermissionRules([]string{category})

	for _, rule := range rules {
		expandedPath := os.ExpandEnv(rule.Path)
		check := pm.checkSinglePath(expandedPath, rule.Mode, rule.Description, rule.Required)
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

// fixCategoryPermissions fixes permissions for a specific category
func (pm *PermissionManager) fixCategoryPermissions(category string) (*PermissionScanResult, error) {
	result := &PermissionScanResult{
		Timestamp: time.Now(),
		Category:  category,
		Checks:    make([]PermissionCheck, 0),
	}

	// Handle special SSH directory scanning and fixing
	if category == "ssh" {
		return pm.fixSSHDirectory(pm.config.SSHDirectory)
	}

	// Get rules for this category
	rules := GetPermissionRules([]string{category})

	for _, rule := range rules {
		expandedPath := os.ExpandEnv(rule.Path)
		check := pm.fixSinglePath(expandedPath, rule.Mode, rule.Description, rule.Required)
		result.Checks = append(result.Checks, check)
		result.TotalChecks++

		if check.Error != "" {
			result.Errors++
		} else if check.NeedsChange && !pm.config.DryRun {
			result.Fixed++
		} else {
			result.Passed++
		}
	}

	return result, nil
}

// fixSSHDirectory fixes permissions in SSH directory
func (pm *PermissionManager) fixSSHDirectory(sshDir string) (*PermissionScanResult, error) {
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
	check := pm.fixSinglePath(sshDir, 0700, "SSH directory", true)
	result.Checks = append(result.Checks, check)
	result.TotalChecks++

	if check.Error != "" {
		result.Errors++
	} else if check.NeedsChange && !pm.config.DryRun {
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
		if pm.shouldExcludePath(path) {
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

		check := pm.fixSinglePath(path, expectedMode, description, false)
		result.Checks = append(result.Checks, check)
		result.TotalChecks++

		if check.Error != "" {
			result.Errors++
		} else if check.NeedsChange && !pm.config.DryRun {
			result.Fixed++
		} else {
			result.Passed++
		}

		return nil
	})

	if err != nil {
		return result, fmt.Errorf("error walking SSH directory: %v", err)
	}

	return result, nil
}

// checkSinglePath checks permissions for a single path
func (pm *PermissionManager) checkSinglePath(path string, expectedMode os.FileMode, description string, required bool) PermissionCheck {
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

// fixSinglePath fixes permissions for a single path
func (pm *PermissionManager) fixSinglePath(path string, expectedMode os.FileMode, description string, required bool) PermissionCheck {
	check := pm.checkSinglePath(path, expectedMode, description, required)

	// If the path doesn't exist or there's an error, return as-is
	if !check.Exists || check.Error != "" {
		return check
	}

	// If permissions are correct, no change needed
	if !check.NeedsChange {
		return check
	}

	// Create backup if enabled
	if pm.config.CreateBackups && !pm.config.DryRun {
		if err := pm.createBackup(path); err != nil {
			check.Error = fmt.Sprintf("Failed to create backup: %v", err)
			return check
		}
	}

	// Fix permissions (unless in dry-run mode)
	if !pm.config.DryRun {
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

// createBackup creates a backup of the file's current permissions
func (pm *PermissionManager) createBackup(path string) error {
	if pm.config.BackupDirectory == "" {
		return nil // No backup directory specified
	}

	// Create backup directory if it doesn't exist
	if err := os.MkdirAll(pm.config.BackupDirectory, shared.SecretDirPerm); err != nil {
		return err
	}

	// Create a simple record of the original permissions
	stat, err := os.Stat(path)
	if err != nil {
		return err
	}

	backupFile := filepath.Join(pm.config.BackupDirectory,
		fmt.Sprintf("permissions_%d.log", time.Now().Unix()))

	backupData := fmt.Sprintf("%s: %o\n", path, stat.Mode()&os.ModePerm)

	return os.WriteFile(backupFile, []byte(backupData), shared.SecretFilePerm)
}

// shouldExcludePath checks if a path should be excluded based on patterns
func (pm *PermissionManager) shouldExcludePath(path string) bool {
	filename := filepath.Base(path)

	for _, pattern := range pm.config.ExcludePatterns {
		if matched, _ := filepath.Match(pattern, filename); matched {
			return true
		}
	}

	return false
}
