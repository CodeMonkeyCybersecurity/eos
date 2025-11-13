// pkg/debug/vault/diag_installation.go
// Installation-related diagnostic checks: binary, configuration, directories, user

package vault

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
	"github.com/hashicorp/hcl/v2/hclsimple"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BinaryDiagnostic checks the vault binary
func BinaryDiagnostic() *debug.Diagnostic {
	return debug.BinaryCheck("Vault", DefaultBinaryPath)
}

// ConfigFileDiagnostic checks the vault configuration file
func ConfigFileDiagnostic() *debug.Diagnostic {
	return debug.FileCheck("Configuration File", DefaultConfigPath, true)
}

// ConfigValidationDiagnostic validates the configuration file using HCL parser
func ConfigValidationDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Configuration Validation",
		Category:    "Configuration",
		Description: "Validate vault.hcl HCL syntax",
		Condition: func(ctx context.Context) bool {
			logger := otelzap.Ctx(ctx)
			// Only run if config exists
			_, cfgErr := os.Stat(DefaultConfigPath)
			canRun := cfgErr == nil
			logger.Debug("Checking config validation prerequisites",
				zap.Bool("config_exists", cfgErr == nil),
				zap.Bool("will_run", canRun))
			return canRun
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			logger.Info("Starting Vault configuration validation",
				zap.String("config_path", DefaultConfigPath))

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			// Read the config file
			configData, err := os.ReadFile(DefaultConfigPath)
			if err != nil {
				logger.Error("Failed to read config file",
					zap.String("config_path", DefaultConfigPath),
					zap.Error(err))
				result.Status = debug.StatusError
				result.Message = "Cannot read configuration file"
				result.Remediation = fmt.Sprintf("Check file permissions: %s", DefaultConfigPath)
				return result, nil
			}

			result.Metadata["config_path"] = DefaultConfigPath
			result.Metadata["config_size"] = len(configData)

			// Define a basic structure to parse Vault config
			// We're just validating HCL syntax, not semantic correctness
			type VaultConfig struct {
				Storage  map[string]interface{} `hcl:"storage,optional"`
				Listener map[string]interface{} `hcl:"listener,optional"`
				UI       *bool                  `hcl:"ui,optional"`
			}

			var config VaultConfig
			err = hclsimple.Decode(DefaultConfigPath, configData, nil, &config)

			if err != nil {
				logger.Error("HCL syntax validation failed",
					zap.String("config_path", DefaultConfigPath),
					zap.Error(err))
				result.Status = debug.StatusError
				result.Message = "HCL syntax error in configuration"
				result.Output = fmt.Sprintf("HCL Parse Error:\n%v", err)
				result.Remediation = fmt.Sprintf("Fix HCL syntax errors in %s", DefaultConfigPath)
			} else {
				logger.Info("Configuration HCL syntax valid",
					zap.String("config_path", DefaultConfigPath))
				result.Status = debug.StatusOK
				result.Message = "HCL syntax is valid"
				result.Output = fmt.Sprintf("✓ HCL syntax valid (%d bytes)\n✓ Successfully parsed Vault configuration", len(configData))
			}

			return result, nil
		},
	}
}

// DataDirectoryDiagnostic checks the vault data directory
func DataDirectoryDiagnostic() *debug.Diagnostic {
	return debug.DirectoryCheck("Data Directory", DefaultDataPath, "vault")
}

// LogDirectoryDiagnostic checks the vault log directory
func LogDirectoryDiagnostic() *debug.Diagnostic {
	return debug.DirectoryCheck("Log Directory", DefaultLogPath, "vault")
}

// UserDiagnostic checks the vault user exists
func UserDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Vault User",
		Category:    "System",
		Description: "Check vault user and group exist",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			// Check user exists
			cmd := exec.CommandContext(ctx, "id", "vault")
			output, err := cmd.CombinedOutput()
			result.Output = string(output)

			if err != nil {
				result.Status = debug.StatusError
				result.Message = "Vault user does not exist"
				result.Remediation = "Create vault user: useradd -r -s /bin/false vault"
			} else {
				result.Status = debug.StatusOK
				result.Message = "Vault user exists"

				// Extract uid/gid
				outputStr := string(output)
				result.Metadata["id_output"] = outputStr
			}

			return result, nil
		},
	}
}
