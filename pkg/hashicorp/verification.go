// pkg/hashicorp/verification.go

package hashicorp

import (
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VerificationResult contains the results of tool verification
type VerificationResult struct {
	Tool        string `json:"tool"`
	Installed   bool   `json:"installed"`
	Version     string `json:"version,omitempty"`
	Path        string `json:"path,omitempty"`
	Error       string `json:"error,omitempty"`
	PluginCount int    `json:"plugin_count,omitempty"`
}

// VerifyInstallation verifies that a HashiCorp tool was installed correctly
func VerifyInstallation(rc *eos_io.RuntimeContext, tool string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔍 Verifying HashiCorp tool installation", zap.String("tool", tool))

	result := &VerificationResult{
		Tool: tool,
	}

	// Check if binary is available
	if err := verifyBinaryExists(rc, tool, result); err != nil {
		logger.Error(" Binary verification failed",
			zap.String("tool", tool),
			zap.Error(err))
		return cerr.Wrapf(err, "verify %s binary", tool)
	}

	// Get version information
	if err := verifyVersion(rc, tool, result); err != nil {
		logger.Error(" Version verification failed",
			zap.String("tool", tool),
			zap.Error(err))
		return cerr.Wrapf(err, "verify %s version", tool)
	}

	// Tool-specific verifications
	if err := verifyToolSpecific(rc, tool, result); err != nil {
		logger.Error(" Tool-specific verification failed",
			zap.String("tool", tool),
			zap.Error(err))
		return cerr.Wrapf(err, "verify %s specific features", tool)
	}

	logger.Info(" Tool verification completed successfully",
		zap.String("tool", result.Tool),
		zap.String("version", result.Version),
		zap.String("path", result.Path),
		zap.Bool("installed", result.Installed))

	return nil
}

// VerifyAllInstallations verifies all installed HashiCorp tools
func VerifyAllInstallations(rc *eos_io.RuntimeContext) ([]VerificationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔍 Verifying all HashiCorp tool installations",
		zap.Strings("tools", SupportedHCLTools))

	results := make([]VerificationResult, 0, len(SupportedHCLTools))

	for _, tool := range SupportedHCLTools {
		result := VerificationResult{
			Tool: tool,
		}

		logger.Info("🔍 Verifying tool", zap.String("tool", tool))

		// Check if binary exists
		if err := verifyBinaryExists(rc, tool, &result); err != nil {
			result.Error = err.Error()
			result.Installed = false
			logger.Warn("Tool not found or not working",
				zap.String("tool", tool),
				zap.Error(err))
		} else {
			// Get version information
			if err := verifyVersion(rc, tool, &result); err != nil {
				result.Error = err.Error()
				logger.Warn("Could not get version",
					zap.String("tool", tool),
					zap.Error(err))
			}

			// Tool-specific verification
			if err := verifyToolSpecific(rc, tool, &result); err != nil {
				logger.Warn("Tool-specific verification had issues",
					zap.String("tool", tool),
					zap.Error(err))
			}
		}

		results = append(results, result)
	}

	// Count successful installations
	successCount := 0
	for _, result := range results {
		if result.Installed {
			successCount++
		}
	}

	logger.Info(" Verification summary",
		zap.Int("total_tools", len(SupportedHCLTools)),
		zap.Int("installed_count", successCount),
		zap.Int("missing_count", len(SupportedHCLTools)-successCount))

	return results, nil
}

// verifyBinaryExists checks if the tool binary is available and executable
func verifyBinaryExists(rc *eos_io.RuntimeContext, tool string, result *VerificationResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("🔍 Checking binary existence", zap.String("tool", tool))

	// Check if command exists using which
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{tool},
	})
	if err != nil {
		logger.Debug(" Binary not found in PATH",
			zap.String("tool", tool),
			zap.Error(err))
		return cerr.Wrapf(err, "binary not found: %s", tool)
	}

	result.Path = strings.TrimSpace(output)
	result.Installed = true

	logger.Debug(" Binary found",
		zap.String("tool", tool),
		zap.String("path", result.Path))

	return nil
}

// verifyVersion gets and validates the version information
func verifyVersion(rc *eos_io.RuntimeContext, tool string, result *VerificationResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("🔍 Getting version information", zap.String("tool", tool))

	// Most HashiCorp tools support --version or version subcommand
	versionArgs := []string{"--version"}
	if tool == "consul" || tool == "nomad" {
		versionArgs = []string{"version"}
	}

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: tool,
		Args:    versionArgs,
	})
	if err != nil {
		logger.Debug(" Failed to get version",
			zap.String("tool", tool),
			zap.Strings("args", versionArgs),
			zap.Error(err))
		return cerr.Wrapf(err, "get version for %s", tool)
	}

	// Extract version from output (usually first line)
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) > 0 {
		result.Version = strings.TrimSpace(lines[0])
	}

	logger.Debug(" Version information obtained",
		zap.String("tool", tool),
		zap.String("version", result.Version))

	return nil
}

// verifyToolSpecific performs tool-specific verification checks
func verifyToolSpecific(rc *eos_io.RuntimeContext, tool string, result *VerificationResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("🔍 Performing tool-specific verification", zap.String("tool", tool))

	switch tool {
	case "terraform":
		return verifyTerraform(rc, result, logger)
	case "vault":
		return verifyVault(rc, result, logger)
	case "consul":
		return verifyConsul(rc, result, logger)
	case "nomad":
		return verifyNomad(rc, result, logger)
	case "packer":
		return verifyPacker(rc, result, logger)
	case "boundary":
		return verifyBoundary(rc, result, logger)
	default:
		logger.Debug("No specific verification for tool", zap.String("tool", tool))
		return nil
	}
}

// verifyTerraform performs Terraform-specific verification
func verifyTerraform(rc *eos_io.RuntimeContext, result *VerificationResult, logger otelzap.LoggerWithCtx) error {
	logger.Debug("🔍 Verifying Terraform configuration")

	// Check providers
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"providers"},
	})
	if err != nil {
		logger.Debug("Could not list Terraform providers", zap.Error(err))
		// Not a critical error for basic verification
		return nil
	}

	// Count available providers
	providerCount := strings.Count(output, "provider[")
	logger.Debug("Terraform providers available", zap.Int("count", providerCount))

	return nil
}

// verifyVault performs Vault-specific verification
func verifyVault(rc *eos_io.RuntimeContext, result *VerificationResult, logger otelzap.LoggerWithCtx) error {
	logger.Debug("🔍 Verifying Vault configuration")

	// Check if Vault can show help (basic functionality test)
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"-h"},
	})
	if err != nil {
		logger.Debug("Vault help command failed", zap.Error(err))
		return cerr.Wrap(err, "vault help command")
	}

	logger.Debug(" Vault basic functionality verified")
	return nil
}

// verifyConsul performs Consul-specific verification
func verifyConsul(rc *eos_io.RuntimeContext, result *VerificationResult, logger otelzap.LoggerWithCtx) error {
	logger.Debug("🔍 Verifying Consul configuration")

	// Check Consul members command (basic functionality)
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"--help"},
	})
	if err != nil {
		logger.Debug("Consul help command failed", zap.Error(err))
		return cerr.Wrap(err, "consul help command")
	}

	logger.Debug(" Consul basic functionality verified")
	return nil
}

// verifyNomad performs Nomad-specific verification
func verifyNomad(rc *eos_io.RuntimeContext, result *VerificationResult, logger otelzap.LoggerWithCtx) error {
	logger.Debug("🔍 Verifying Nomad configuration")

	// Check Nomad help
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"-h"},
	})
	if err != nil {
		logger.Debug("Nomad help command failed", zap.Error(err))
		return cerr.Wrap(err, "nomad help command")
	}

	logger.Debug(" Nomad basic functionality verified")
	return nil
}

// verifyPacker performs Packer-specific verification
func verifyPacker(rc *eos_io.RuntimeContext, result *VerificationResult, logger otelzap.LoggerWithCtx) error {
	logger.Debug("🔍 Verifying Packer configuration")

	// Check Packer plugins
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "packer",
		Args:    []string{"plugins", "installed"},
	})
	if err != nil {
		logger.Debug("Could not list Packer plugins", zap.Error(err))
		// Not critical for basic verification
		return nil
	}

	// Count installed plugins
	pluginCount := strings.Count(output, "* ")
	result.PluginCount = pluginCount
	logger.Debug("Packer plugins installed", zap.Int("count", pluginCount))

	return nil
}

// verifyBoundary performs Boundary-specific verification
func verifyBoundary(rc *eos_io.RuntimeContext, result *VerificationResult, logger otelzap.LoggerWithCtx) error {
	logger.Debug("🔍 Verifying Boundary configuration")

	// Check Boundary help
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "boundary",
		Args:    []string{"-h"},
	})
	if err != nil {
		logger.Debug("Boundary help command failed", zap.Error(err))
		return cerr.Wrap(err, "boundary help command")
	}

	logger.Debug(" Boundary basic functionality verified")
	return nil
}
