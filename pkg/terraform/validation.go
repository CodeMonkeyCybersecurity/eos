// pkg/terraform/validation.go

package terraform

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ComprehensiveTerraformValidation performs complete Terraform prerequisite validation
func ComprehensiveTerraformValidation(rc *eos_io.RuntimeContext, prereqs TerraformPrerequisites) (*TerraformValidationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting comprehensive Terraform validation")

	result := &TerraformValidationResult{
		ProviderValidations: []ProviderValidation{},
		Errors:              []string{},
		Warnings:            []string{},
	}

	// ASSESS - Check all prerequisites
	logger.Info("Assessing Terraform prerequisites")

	// 1. Version Compatibility Check
	if err := validateTerraformVersion(rc, prereqs, result); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Version validation failed: %v", err))
		return result, err
	}

	// 2. Provider Authentication Check
	if err := validateProviderAuthentication(rc, prereqs, result); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Provider validation failed: %v", err))
		// Continue with other checks even if providers fail
	}

	// 3. State File Integrity Check
	if err := validateStateIntegrity(rc, prereqs, result); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("State validation warning: %v", err))
		// State issues are warnings, not errors
	}

	// 4. Resource Quota Check
	if err := validateResourceQuotas(rc, prereqs, result); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Quota validation warning: %v", err))
		// Quota issues are warnings
	}

	// EVALUATE - Determine overall validation status
	result.VersionCompatible = (result.VersionInfo != nil)
	result.ProvidersValid = allProvidersValid(result.ProviderValidations)
	result.StateValid = (result.StateValidation != nil && result.StateValidation.IntegrityValid)
	result.QuotasValid = (result.QuotaValidation != nil && result.QuotaValidation.Error == "")

	logger.Info("Terraform validation completed",
		zap.Bool("version_compatible", result.VersionCompatible),
		zap.Bool("providers_valid", result.ProvidersValid),
		zap.Bool("state_valid", result.StateValid),
		zap.Bool("quotas_valid", result.QuotasValid),
		zap.Int("error_count", len(result.Errors)),
		zap.Int("warning_count", len(result.Warnings)))

	if len(result.Errors) > 0 {
		return result, eos_err.NewUserError("Terraform validation failed with %d errors", len(result.Errors))
	}

	return result, nil
}

// validateTerraformVersion checks Terraform version compatibility
func validateTerraformVersion(rc *eos_io.RuntimeContext, prereqs TerraformPrerequisites, result *TerraformValidationResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Validating Terraform version compatibility")

	// Check if terraform binary exists
	if _, err := exec.LookPath("terraform"); err != nil {
		return eos_err.NewUserError("Terraform not found in PATH")
	}

	// Get version information
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"version", "-json"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to get Terraform version: %w", err)
	}

	// Parse version JSON
	var versionInfo TerraformVersionInfo
	if err := json.Unmarshal([]byte(output), &versionInfo); err != nil {
		return fmt.Errorf("failed to parse Terraform version output: %w", err)
	}

	result.VersionInfo = &versionInfo

	// Validate version range
	currentVersion := versionInfo.Version
	if !isVersionInRange(currentVersion, prereqs.MinVersion, prereqs.MaxVersion) {
		return eos_err.NewUserError("Terraform version %s is not compatible. Required: %s - %s",
			currentVersion, prereqs.MinVersion, prereqs.MaxVersion)
	}

	logger.Info("Terraform version validated",
		zap.String("version", currentVersion),
		zap.String("platform", versionInfo.Platform))

	return nil
}

// validateProviderAuthentication checks provider credentials and permissions
func validateProviderAuthentication(rc *eos_io.RuntimeContext, prereqs TerraformPrerequisites, result *TerraformValidationResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Validating provider authentication")

	for _, provider := range prereqs.RequiredProviders {
		validation := ProviderValidation{
			Name:          provider,
			LastValidated: time.Now(),
		}

		switch {
		case strings.Contains(provider, "hetzner"):
			err := validateHetznerProvider(rc, &validation)
			if err != nil {
				validation.Error = err.Error()
				logger.Warn("Hetzner provider validation failed", zap.Error(err))
			}
		case strings.Contains(provider, "consul"):
			err := validateConsulProvider(rc, &validation)
			if err != nil {
				validation.Error = err.Error()
				logger.Warn("Consul provider validation failed", zap.Error(err))
			}
		case strings.Contains(provider, "vault"):
			err := validateVaultProvider(rc, &validation)
			if err != nil {
				validation.Error = err.Error()
				logger.Warn("Vault provider validation failed", zap.Error(err))
			}
		default:
			validation.Error = "Unknown provider type"
		}

		result.ProviderValidations = append(result.ProviderValidations, validation)
	}

	return nil
}

// validateStateIntegrity checks Terraform state file integrity
func validateStateIntegrity(rc *eos_io.RuntimeContext, prereqs TerraformPrerequisites, result *TerraformValidationResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Validating state file integrity")

	stateValidation := &StateValidation{
		LastModified: time.Now(),
	}

	// Check working directory
	if _, err := os.Stat(prereqs.WorkingDirectory); os.IsNotExist(err) {
		logger.Debug("Working directory does not exist, will be created",
			zap.String("directory", prereqs.WorkingDirectory))
		stateValidation.Error = "Working directory does not exist"
		result.StateValidation = stateValidation
		return nil // Not an error, just needs initialization
	}

	// Check for state file
	statePath := filepath.Join(prereqs.WorkingDirectory, "terraform.tfstate")
	if stat, err := os.Stat(statePath); err == nil {
		stateValidation.Exists = true
		stateValidation.Size = stat.Size()
		stateValidation.LastModified = stat.ModTime()

		// Validate state file JSON structure
		if err := validateStateFileStructure(rc, statePath, stateValidation); err != nil {
			stateValidation.Error = err.Error()
			logger.Warn("State file validation failed", zap.Error(err))
		} else {
			stateValidation.IntegrityValid = true
			stateValidation.VersionValid = true
		}

		// Check for backup
		backupPath := statePath + ".backup"
		if _, err := os.Stat(backupPath); err == nil {
			stateValidation.BackupExists = true
		}
	} else {
		logger.Debug("State file does not exist, fresh deployment",
			zap.String("state_path", statePath))
		stateValidation.Exists = false
		stateValidation.IntegrityValid = true // Fresh state is valid
	}

	result.StateValidation = stateValidation
	logger.Debug("State validation completed",
		zap.Bool("exists", stateValidation.Exists),
		zap.Bool("valid", stateValidation.IntegrityValid),
		zap.Int64("size", stateValidation.Size))

	return nil
}

// validateResourceQuotas checks provider resource limits and usage
func validateResourceQuotas(rc *eos_io.RuntimeContext, prereqs TerraformPrerequisites, result *TerraformValidationResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Validating resource quotas")

	quotaValidation := &QuotaValidation{
		RateLimitStatus: "unknown",
	}

	// Check Hetzner DNS quota if using Hetzner provider
	for _, provider := range prereqs.RequiredProviders {
		if strings.Contains(provider, "hetzner") {
			if err := checkHetznerQuotas(rc, quotaValidation); err != nil {
				quotaValidation.Error = err.Error()
				logger.Warn("Hetzner quota check failed", zap.Error(err))
			}
			break
		}
	}

	result.QuotaValidation = quotaValidation
	return nil
}

// ValidateTerraformForHecate performs Hecate-specific Terraform validation
func ValidateTerraformForHecate(rc *eos_io.RuntimeContext) (*TerraformValidationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Performing Hecate-specific Terraform validation")

	// Use default Hecate prerequisites
	return ComprehensiveTerraformValidation(rc, DefaultHecatePrerequisites)
}
