// pkg/hashicorp/tools.go

package hashicorp

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SupportedHCLTools defines the HashiCorp tools that can be installed
var SupportedHCLTools = []string{
	"terraform",
	"vault",
	"consul",
	"nomad",
	"packer",
	"boundary",
}

// InstallTool installs a specific HashiCorp tool with comprehensive error handling
func InstallTool(rc *eos_io.RuntimeContext, tool string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Starting HashiCorp tool installation",
		zap.String("tool", tool),
		zap.Strings("supported_tools", SupportedHCLTools))

	if !IsToolSupported(tool) {
		err := fmt.Errorf("unsupported HashiCorp tool: %s", tool)
		logger.Error(" Tool not supported",
			zap.String("tool", tool),
			zap.Strings("supported_tools", SupportedHCLTools),
			zap.Error(err))
		return cerr.Wrap(err, "validate tool support")
	}

	logger.Info(" Tool validation passed", zap.String("tool", tool))

	// Install prerequisites
	logger.Info(" Installing prerequisites")
	if err := installPrerequisites(rc); err != nil {
		logger.Error(" Failed to install prerequisites", zap.Error(err))
		return cerr.Wrap(err, "install prerequisites")
	}
	logger.Info(" Prerequisites installed successfully")

	// Install GPG key
	logger.Info(" Installing HashiCorp GPG key")
	if err := InstallGPGKey(rc); err != nil {
		logger.Error(" Failed to install GPG key", zap.Error(err))
		return cerr.Wrap(err, "install GPG key")
	}
	logger.Info(" GPG key installed successfully")

	// Add repository
	logger.Info(" Adding HashiCorp repository")
	if err := AddRepository(rc); err != nil {
		logger.Error(" Failed to add repository", zap.Error(err))
		return cerr.Wrap(err, "add repository")
	}
	logger.Info(" Repository added successfully")

	// Install specific tool
	logger.Info(" Installing specific tool", zap.String("tool", tool))
	if err := installSpecificTool(rc, tool); err != nil {
		logger.Error(" Failed to install tool",
			zap.String("tool", tool),
			zap.Error(err))
		return cerr.Wrapf(err, "install %s", tool)
	}
	logger.Info(" Tool installation completed", zap.String("tool", tool))

	// Verify installation
	logger.Info(" Verifying installation", zap.String("tool", tool))
	if err := VerifyInstallation(rc, tool); err != nil {
		logger.Error(" Installation verification failed",
			zap.String("tool", tool),
			zap.Error(err))
		return cerr.Wrapf(err, "verify %s installation", tool)
	}
	logger.Info(" Installation verification passed", zap.String("tool", tool))

	logger.Info(" Successfully installed HashiCorp tool", zap.String("tool", tool))
	return nil
}

// InstallAllTools installs all supported HashiCorp tools
func InstallAllTools(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Starting installation of all HashiCorp tools",
		zap.Strings("tools", SupportedHCLTools),
		zap.Int("tool_count", len(SupportedHCLTools)))

	// Install prerequisites once for all tools
	logger.Info(" Installing prerequisites for all tools")
	if err := installPrerequisites(rc); err != nil {
		logger.Error(" Failed to install prerequisites", zap.Error(err))
		return cerr.Wrap(err, "install prerequisites")
	}

	logger.Info(" Installing HashiCorp GPG key")
	if err := InstallGPGKey(rc); err != nil {
		logger.Error(" Failed to install GPG key", zap.Error(err))
		return cerr.Wrap(err, "install GPG key")
	}

	logger.Info(" Adding HashiCorp repository")
	if err := AddRepository(rc); err != nil {
		logger.Error(" Failed to add repository", zap.Error(err))
		return cerr.Wrap(err, "add repository")
	}

	// Install each tool individually
	successfulTools := []string{}
	failedTools := map[string]error{}

	for _, tool := range SupportedHCLTools {
		logger.Info(" Installing tool",
			zap.String("tool", tool),
			zap.Int("remaining", len(SupportedHCLTools)-len(successfulTools)-len(failedTools)))

		if err := installSpecificTool(rc, tool); err != nil {
			logger.Error(" Failed to install tool",
				zap.String("tool", tool),
				zap.Error(err))
			failedTools[tool] = err
			continue
		}

		if err := VerifyInstallation(rc, tool); err != nil {
			logger.Error(" Tool verification failed",
				zap.String("tool", tool),
				zap.Error(err))
			failedTools[tool] = err
			continue
		}

		successfulTools = append(successfulTools, tool)
		logger.Info(" Tool installed successfully", zap.String("tool", tool))
	}

	// Report results
	logger.Info(" Installation summary",
		zap.Strings("successful_tools", successfulTools),
		zap.Int("successful_count", len(successfulTools)),
		zap.Int("failed_count", len(failedTools)))

	if len(failedTools) > 0 {
		failedNames := make([]string, 0, len(failedTools))
		for name := range failedTools {
			failedNames = append(failedNames, name)
		}
		logger.Error(" Some tools failed to install",
			zap.Strings("failed_tools", failedNames))

		// Return error with details about first failure
		for tool, err := range failedTools {
			return cerr.Wrapf(err, "install all tools - %s failed", tool)
		}
	}

	logger.Info(" Successfully installed all HashiCorp tools",
		zap.Strings("tools", successfulTools))
	return nil
}

// IsToolSupported checks if a tool is in the supported list
func IsToolSupported(tool string) bool {
	for _, supportedTool := range SupportedHCLTools {
		if tool == supportedTool {
			return true
		}
	}
	return false
}

// installPrerequisites installs the required system packages
func installPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Installing system prerequisites")

	prerequisites := []string{"wget", "gpg", "lsb-release"}

	distro := platform.DetectLinuxDistro(rc)
	logger.Info(" Detected Linux distribution", zap.String("distro", distro))

	switch distro {
	case "debian":
		args := append([]string{"install", "-y"}, prerequisites...)
		if err := execute.RunSimple(rc.Ctx, "apt-get", args...); err != nil {
			logger.Error(" Failed to install prerequisites via apt-get",
				zap.Strings("packages", prerequisites),
				zap.Error(err))
			return cerr.Wrap(err, "install debian prerequisites")
		}
	case "rhel":
		args := append([]string{"install", "-y"}, prerequisites...)
		if err := execute.RunSimple(rc.Ctx, "dnf", args...); err != nil {
			logger.Error(" Failed to install prerequisites via dnf",
				zap.Strings("packages", prerequisites),
				zap.Error(err))
			return cerr.Wrap(err, "install rhel prerequisites")
		}
	default:
		err := fmt.Errorf("unsupported distribution: %s", distro)
		logger.Error(" Unsupported Linux distribution",
			zap.String("distro", distro),
			zap.Error(err))
		return cerr.Wrap(err, "check distribution support")
	}

	logger.Info(" Prerequisites installed successfully",
		zap.Strings("packages", prerequisites),
		zap.String("distro", distro))
	return nil
}

// installSpecificTool installs a single HashiCorp tool
func installSpecificTool(rc *eos_io.RuntimeContext, tool string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Installing specific HashiCorp tool", zap.String("tool", tool))

	distro := platform.DetectLinuxDistro(rc)

	switch distro {
	case "debian":
		if err := execute.RunSimple(rc.Ctx, "apt-get", "update"); err != nil {
			logger.Error(" Failed to update package lists", zap.Error(err))
			return cerr.Wrap(err, "update package lists")
		}

		if err := execute.RunSimple(rc.Ctx, "apt-get", "install", "-y", tool); err != nil {
			logger.Error(" Failed to install tool via apt-get",
				zap.String("tool", tool),
				zap.Error(err))
			return cerr.Wrapf(err, "install %s via apt-get", tool)
		}
	case "rhel":
		if err := execute.RunSimple(rc.Ctx, "dnf", "install", "-y", tool); err != nil {
			logger.Error(" Failed to install tool via dnf",
				zap.String("tool", tool),
				zap.Error(err))
			return cerr.Wrapf(err, "install %s via dnf", tool)
		}
	default:
		err := fmt.Errorf("unsupported distribution: %s", distro)
		logger.Error(" Cannot install on unsupported distribution",
			zap.String("distro", distro),
			zap.String("tool", tool),
			zap.Error(err))
		return cerr.Wrap(err, "check distribution support")
	}

	logger.Info(" Tool package installation completed",
		zap.String("tool", tool),
		zap.String("distro", distro))
	return nil
}

// GetSupportedToolsString returns a comma-separated string of supported tools
func GetSupportedToolsString() string {
	return strings.Join(SupportedHCLTools, ", ")
}
