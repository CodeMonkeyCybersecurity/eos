// pkg/vault/fix/fix.go
// Vault repair and fix operations following Assess → Intervene → Evaluate pattern

package fix

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Config holds the fix configuration options
type Config struct {
	DryRun          bool
	CleanupBinaries bool
	FixPermissions  bool
	RepairConfig    bool
	All             bool
}

// RepairResult holds the results of a repair operation
type RepairResult struct {
	IssuesFound int
	IssuesFixed int
	Errors      []error
}

// RunFixes performs Vault repairs following Assess → Intervene → Evaluate pattern
func RunFixes(rc *eos_io.RuntimeContext, config *Config) (*RepairResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Vault repair",
		zap.Bool("dry_run", config.DryRun))

	if config.DryRun {
		logger.Info("DRY-RUN MODE: No changes will be made")
	}

	// Default: run all repairs if no specific flag is set
	runBinaries := config.CleanupBinaries || config.All || (!config.CleanupBinaries && !config.FixPermissions && !config.RepairConfig)
	runPermissions := config.FixPermissions || config.All
	runConfig := config.RepairConfig || config.All

	result := &RepairResult{
		IssuesFound: 0,
		IssuesFixed: 0,
		Errors:      []error{},
	}

	// ASSESS & INTERVENE: Cleanup duplicate binaries
	if runBinaries {
		logger.Info("Checking for duplicate vault binaries")
		found, fixed, err := RepairDuplicateBinaries(rc, config.DryRun)
		result.IssuesFound += found
		result.IssuesFixed += fixed
		if err != nil {
			logger.Warn("Binary cleanup encountered errors", zap.Error(err))
			result.Errors = append(result.Errors, err)
		}
	}

	// ASSESS & INTERVENE: Fix permissions
	if runPermissions {
		logger.Info("Checking file permissions")
		found, fixed, err := RepairFilePermissions(rc, config.DryRun)
		result.IssuesFound += found
		result.IssuesFixed += fixed
		if err != nil {
			logger.Warn("Permission repair encountered errors", zap.Error(err))
			result.Errors = append(result.Errors, err)
		}
	}

	// ASSESS & INTERVENE: Fix configuration
	if runConfig {
		logger.Info("Checking configuration files")
		found, fixed, err := RepairConfiguration(rc, config.DryRun)
		result.IssuesFound += found
		result.IssuesFixed += fixed
		if err != nil {
			logger.Warn("Configuration repair encountered errors", zap.Error(err))
			result.Errors = append(result.Errors, err)
		}
	}

	// EVALUATE
	logger.Info("Vault repair completed",
		zap.Int("issues_found", result.IssuesFound),
		zap.Int("issues_fixed", result.IssuesFixed),
		zap.Bool("dry_run", config.DryRun))

	return result, nil
}

// RepairDuplicateBinaries finds and removes duplicate vault binaries
func RepairDuplicateBinaries(rc *eos_io.RuntimeContext, dryRun bool) (int, int, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking for duplicate Vault binaries")

	// ASSESS: Find all vault binaries
	binaries, err := vault.FindVaultBinaries(rc)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to find binaries: %w", err)
	}

	// Count duplicates (anything not at standard path)
	duplicates := 0
	duplicateList := []vault.BinaryLocation{}
	for _, binary := range binaries {
		if binary.Path != shared.VaultBinaryPath {
			duplicates++
			duplicateList = append(duplicateList, binary)
		}
	}

	if duplicates == 0 {
		logger.Info("No duplicate binaries found")
		return 0, 0, nil
	}

	logger.Info("Found duplicate vault binaries",
		zap.Int("count", duplicates),
		zap.Any("duplicates", duplicateList))

	if dryRun {
		logger.Info("Would remove duplicate binaries (dry-run)",
			zap.Int("count", duplicates))
		return duplicates, duplicates, nil
	}

	// INTERVENE: Actually remove duplicates
	if err := vault.CleanupDuplicateBinaries(rc, shared.VaultBinaryPath); err != nil {
		return duplicates, 0, fmt.Errorf("failed to cleanup binaries: %w", err)
	}

	logger.Info("Removed duplicate binaries",
		zap.Int("count", duplicates))
	return duplicates, duplicates, nil
}

// RepairFilePermissions fixes file permissions and ownership
func RepairFilePermissions(rc *eos_io.RuntimeContext, dryRun bool) (int, int, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking file permissions")

	// ASSESS: Define expected permissions for Vault files
	fileChecks := []struct {
		path         string
		expectedPerm os.FileMode
		description  string
	}{
		{shared.TLSCrt, 0644, "TLS certificate"},
		{shared.TLSKey, 0600, "TLS private key"},
		{shared.VaultConfigPath, 0640, "Vault configuration"},
		{shared.VaultDataPath, 0750, "Vault data directory"},
		{"/var/log/vault", 0750, "Vault log directory"},
	}

	issuesFound := 0
	issuesFixed := 0
	permissionIssues := []string{}

	for _, check := range fileChecks {
		info, err := os.Stat(check.path)
		if err != nil {
			if os.IsNotExist(err) {
				logger.Debug("File does not exist", zap.String("path", check.path))
				continue
			}
			logger.Warn("Cannot check file", zap.String("path", check.path), zap.Error(err))
			continue
		}

		actualPerm := info.Mode().Perm()
		if actualPerm != check.expectedPerm {
			issuesFound++
			issueMsg := fmt.Sprintf("%s has incorrect permissions: %04o (expected %04o) at %s",
				check.description, actualPerm, check.expectedPerm, check.path)
			permissionIssues = append(permissionIssues, issueMsg)

			logger.Warn("Incorrect file permissions",
				zap.String("path", check.path),
				zap.String("description", check.description),
				zap.String("actual", fmt.Sprintf("%04o", actualPerm)),
				zap.String("expected", fmt.Sprintf("%04o", check.expectedPerm)))

			// INTERVENE: Fix permissions
			if !dryRun {
				if err := os.Chmod(check.path, check.expectedPerm); err != nil {
					logger.Error("Failed to fix permissions",
						zap.String("path", check.path),
						zap.Error(err))
				} else {
					issuesFixed++
					logger.Info("Fixed file permissions",
						zap.String("path", check.path),
						zap.String("new_permissions", fmt.Sprintf("%04o", check.expectedPerm)))
				}
			} else {
				issuesFixed++ // Would fix in dry-run mode
			}
		}
	}

	if issuesFound == 0 {
		logger.Info("All file permissions are correct")
	} else {
		logger.Info("File permission check completed",
			zap.Int("issues_found", issuesFound),
			zap.Int("issues_fixed", issuesFixed),
			zap.Strings("issues", permissionIssues))
	}

	return issuesFound, issuesFixed, nil
}

// RepairConfiguration validates and repairs configuration files
func RepairConfiguration(rc *eos_io.RuntimeContext, dryRun bool) (int, int, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking configuration files")

	// ASSESS: Validate config
	result, err := vault.ValidateConfigWithFallback(rc, shared.VaultConfigPath)
	if err != nil {
		return 1, 0, fmt.Errorf("configuration validation failed: %w", err)
	}

	issuesFound := len(result.Errors)
	if issuesFound == 0 {
		logger.Info("Configuration is valid")
		return 0, 0, nil
	}

	logger.Warn("Configuration has errors",
		zap.Int("error_count", issuesFound),
		zap.Strings("errors", result.Errors))

	// Currently we don't have auto-fix for config errors
	// User needs to manually fix configuration issues
	logger.Info("Configuration errors require manual intervention",
		zap.String("suggestion", "Run 'sudo eos check vault --config' for detailed validation"))

	return issuesFound, 0, nil
}

// GetDuplicateBinaries returns a list of duplicate vault binaries (for display purposes)
func GetDuplicateBinaries(rc *eos_io.RuntimeContext) ([]vault.BinaryLocation, error) {
	binaries, err := vault.FindVaultBinaries(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to find binaries: %w", err)
	}

	duplicates := []vault.BinaryLocation{}
	for _, binary := range binaries {
		if binary.Path != shared.VaultBinaryPath {
			duplicates = append(duplicates, binary)
		}
	}

	return duplicates, nil
}
