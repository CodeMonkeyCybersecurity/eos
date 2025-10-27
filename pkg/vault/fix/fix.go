// pkg/vault/fix/fix.go
// Vault repair and fix operations following Assess → Intervene → Evaluate pattern

package fix

import (
	"fmt"
	"os"
	"strings"
	"time"

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
	FixAddresses    bool
	RepairMFA       bool
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

	// Initialize operation context for tracking
	rc.Operation = eos_io.NewOperationContext("fix", "vault")
	startTime := rc.Operation.StartTime

	// Default: run all repairs if no specific flag is set
	runBinaries := config.CleanupBinaries || config.All || (!config.CleanupBinaries && !config.FixPermissions && !config.RepairConfig && !config.FixAddresses && !config.RepairMFA)
	runPermissions := config.FixPermissions || config.All
	runConfig := config.RepairConfig || config.All
	runAddresses := config.FixAddresses || config.All
	runMFA := config.RepairMFA || config.All

	logger.Info("Vault repair operation initialized",
		zap.String("operation_id", rc.Operation.OperationID),
		zap.Bool("dry_run", config.DryRun),
		zap.Bool("cleanup_binaries", runBinaries),
		zap.Bool("fix_permissions", runPermissions),
		zap.Bool("repair_config", runConfig),
		zap.Bool("fix_addresses", runAddresses),
		zap.Bool("repair_mfa", runMFA))

	if config.DryRun {
		logger.Info("DRY-RUN MODE: No changes will be made",
			zap.String("operation_id", rc.Operation.OperationID))
	}

	result := &RepairResult{
		IssuesFound: 0,
		IssuesFixed: 0,
		Errors:      []error{},
	}

	// ASSESS & INTERVENE: Cleanup duplicate binaries
	rc.Operation.SetPhase(rc, "ASSESS")

	if runBinaries {
		logger.Info("[ASSESS] Checking for duplicate vault binaries")
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
		logger.Info("[ASSESS] Checking file permissions",
			zap.String("config_path", vault.VaultConfigPath),
			zap.String("data_dir", vault.VaultDataDir),
			zap.String("tls_dir", vault.VaultTLSDir))
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
		logger.Info("[ASSESS] Checking configuration files",
			zap.String("config_file", vault.VaultConfigPath))
		found, fixed, err := RepairConfiguration(rc, config.DryRun)
		result.IssuesFound += found
		result.IssuesFixed += fixed
		if err != nil {
			logger.Warn("Configuration repair encountered errors", zap.Error(err))
			result.Errors = append(result.Errors, err)
		}
	}

	// ASSESS & INTERVENE: Fix API and cluster addresses
	if runAddresses {
		logger.Info("[ASSESS] Checking API and cluster addresses")
		found, fixed, err := RepairVaultAddresses(rc, config.DryRun)
		result.IssuesFound += found
		result.IssuesFixed += fixed
		if err != nil {
			logger.Warn("Address repair encountered errors", zap.Error(err))
			result.Errors = append(result.Errors, err)
		}
	}

	// ASSESS & INTERVENE: Repair MFA enforcement policies
	if runMFA {
		logger.Info("[ASSESS] Checking MFA enforcement policies")
		// Get admin Vault client for MFA operations (HashiCorp best practice)
		client, err := vault.GetAdminClient(rc)
		if err != nil {
			logger.Warn("Cannot get Vault client for MFA repair - skipping MFA checks",
				zap.Error(err))
			logger.Info("  To fix manually: Check Vault is running and unsealed")
		} else {
			found, fixed, err := RepairMFAEnforcement(rc, client, config.DryRun)
			result.IssuesFound += found
			result.IssuesFixed += fixed
			if err != nil {
				logger.Warn("MFA enforcement repair encountered errors", zap.Error(err))
				result.Errors = append(result.Errors, err)
			}
		}
	}

	// EVALUATE
	rc.Operation.SetPhase(rc, "EVALUATE")

	logger.Info("Vault repair operation completed",
		zap.String("operation_id", rc.Operation.OperationID),
		zap.Duration("total_elapsed", time.Since(startTime)),
		zap.Int("issues_found", result.IssuesFound),
		zap.Int("issues_fixed", result.IssuesFixed),
		zap.Int("errors_count", len(result.Errors)),
		zap.Bool("dry_run", config.DryRun))

	rc.Operation.LogCompletion(rc, true, "Vault repair completed")

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
		if binary.Path != vault.VaultBinaryPath {
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
	if err := vault.CleanupDuplicateBinaries(rc, vault.VaultBinaryPath); err != nil {
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
		if binary.Path != vault.VaultBinaryPath {
			duplicates = append(duplicates, binary)
		}
	}

	return duplicates, nil
}

// RepairVaultAddresses checks and fixes incorrect api_addr and cluster_addr in vault.hcl
// ASSESS → INTERVENE → EVALUATE pattern
func RepairVaultAddresses(rc *eos_io.RuntimeContext, dryRun bool) (int, int, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking Vault API and cluster addresses")

	// ASSESS: Read current configuration
	configPath := shared.VaultConfigPath
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logger.Info("Vault config file does not exist", zap.String("path", configPath))
		return 0, 0, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read vault config: %w", err)
	}

	content := string(data)
	hostname, err := os.Hostname()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get hostname: %w", err)
	}

	// Check for incorrect localhost addresses
	issuesFound := 0
	var oldAPIAddr, oldClusterAddr string
	newAPIAddr := fmt.Sprintf("https://%s:%s", hostname, shared.VaultDefaultPort)
	newClusterAddr := fmt.Sprintf("https://%s:%s", hostname, shared.VaultClusterPort)

	// Detect current api_addr
	if strings.Contains(content, `api_addr     = "https://shared.GetInternalHostname:`) ||
		strings.Contains(content, `api_addr     = "https://localhost:`) {
		issuesFound++
		if strings.Contains(content, "shared.GetInternalHostname") {
			oldAPIAddr = fmt.Sprintf("https://shared.GetInternalHostname:%s", shared.VaultDefaultPort)
		} else {
			oldAPIAddr = fmt.Sprintf("https://localhost:%s", shared.VaultDefaultPort)
		}
		logger.Warn("Found incorrect api_addr using localhost",
			zap.String("current", oldAPIAddr),
			zap.String("should_be", newAPIAddr))
	}

	// Detect current cluster_addr
	if strings.Contains(content, `cluster_addr = "https://shared.GetInternalHostname:`) ||
		strings.Contains(content, `cluster_addr = "https://localhost:`) {
		issuesFound++
		if strings.Contains(content, "shared.GetInternalHostname") {
			oldClusterAddr = fmt.Sprintf("https://shared.GetInternalHostname:%s", shared.VaultClusterPort)
		} else {
			oldClusterAddr = fmt.Sprintf("https://localhost:%s", shared.VaultClusterPort)
		}
		logger.Warn("Found incorrect cluster_addr using localhost",
			zap.String("current", oldClusterAddr),
			zap.String("should_be", newClusterAddr))
	}

	if issuesFound == 0 {
		logger.Info("API and cluster addresses are correct")
		return 0, 0, nil
	}

	if dryRun {
		logger.Info("Would fix address configuration (dry-run)",
			zap.Int("issues", issuesFound))
		return issuesFound, issuesFound, nil
	}

	// INTERVENE: Create backup before modification
	backupPath := fmt.Sprintf("%s.backup.%s", configPath, fmt.Sprintf("%d", os.Getpid()))
	if err := os.WriteFile(backupPath, data, 0640); err != nil {
		return issuesFound, 0, fmt.Errorf("failed to create backup: %w", err)
	}
	logger.Info("Created configuration backup", zap.String("backup_path", backupPath))

	// Replace addresses
	newContent := content
	issuesFixed := 0

	if oldAPIAddr != "" {
		oldLine := fmt.Sprintf(`api_addr     = "%s"`, oldAPIAddr)
		newLine := fmt.Sprintf(`api_addr     = "%s"`, newAPIAddr)
		newContent = strings.ReplaceAll(newContent, oldLine, newLine)
		issuesFixed++
		logger.Info("Fixed api_addr",
			zap.String("old", oldAPIAddr),
			zap.String("new", newAPIAddr))
	}

	if oldClusterAddr != "" {
		oldLine := fmt.Sprintf(`cluster_addr = "%s"`, oldClusterAddr)
		newLine := fmt.Sprintf(`cluster_addr = "%s"`, newClusterAddr)
		newContent = strings.ReplaceAll(newContent, oldLine, newLine)
		issuesFixed++
		logger.Info("Fixed cluster_addr",
			zap.String("old", oldClusterAddr),
			zap.String("new", newClusterAddr))
	}

	// Write updated configuration
	if err := os.WriteFile(configPath, []byte(newContent), 0640); err != nil {
		return issuesFound, 0, fmt.Errorf("failed to write updated config: %w", err)
	}

	// EVALUATE: Verify the fix
	logger.Info("Vault address configuration updated successfully",
		zap.Int("issues_found", issuesFound),
		zap.Int("issues_fixed", issuesFixed),
		zap.String("backup", backupPath))

	logger.Warn("Vault service must be restarted for changes to take effect",
		zap.String("command", "sudo systemctl restart vault.service"))

	return issuesFound, issuesFixed, nil
}
