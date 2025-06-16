// cmd/create/hcl.go

package create

import (
	"fmt"
	"os/exec"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SupportedHCLTools defines the HashiCorp tools that can be installed
var SupportedHCLTools = []string{"terraform", "vault", "consul", "nomad", "packer"}

var hclCmd = &cobra.Command{
	Use:   "hcl [tool]",
	Short: "Install HashiCorp tools (terraform, vault, consul, nomad, packer)",
	Long: `Install HashiCorp tools using their official APT repository.

Supported tools: terraform, vault, consul, nomad, packer

Examples:
  eos create hcl terraform
  eos create hcl vault
  eos create hcl consul
  eos create hcl all`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		tool := args[0]
		
		if tool == "all" {
			return installAllHCLTools(rc)
		}
		
		return installHCLTool(rc, tool)
	}),
}

var terraformCmd = &cobra.Command{
	Use:   "terraform",
	Short: "Install Terraform",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return installHCLTool(rc, "terraform")
	}),
}

var consulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Install Consul",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return installHCLTool(rc, "consul")
	}),
}

var nomadCmd = &cobra.Command{
	Use:   "nomad",
	Short: "Install Nomad",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return installHCLTool(rc, "nomad")
	}),
}

var packerCmd = &cobra.Command{
	Use:   "packer",
	Short: "Install Packer",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return installHCLTool(rc, "packer")
	}),
}

func init() {
	CreateCmd.AddCommand(hclCmd)
	CreateCmd.AddCommand(terraformCmd)
	CreateCmd.AddCommand(consulCmd)
	CreateCmd.AddCommand(nomadCmd)
	CreateCmd.AddCommand(packerCmd)
}

func installHCLTool(rc *eos_io.RuntimeContext, tool string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	if !isHCLToolSupported(tool) {
		return fmt.Errorf("unsupported HashiCorp tool: %s. Supported tools: %s", tool, strings.Join(SupportedHCLTools, ", "))
	}

	logger.Info("Installing HashiCorp tool", zap.String("tool", tool))

	if err := installHCLPrerequisites(rc); err != nil {
		return fmt.Errorf("failed to install prerequisites: %w", err)
	}

	if err := installHashiCorpGPGKey(rc); err != nil {
		return fmt.Errorf("failed to install HashiCorp GPG key: %w", err)
	}

	if err := addHashiCorpRepository(rc); err != nil {
		return fmt.Errorf("failed to add HashiCorp repository: %w", err)
	}

	if err := installSpecificHCLTool(rc, tool); err != nil {
		return fmt.Errorf("failed to install %s: %w", tool, err)
	}

	if err := verifyHCLInstallation(rc, tool); err != nil {
		return fmt.Errorf("failed to verify %s installation: %w", tool, err)
	}

	logger.Info("Successfully installed HashiCorp tool", zap.String("tool", tool))
	return nil
}

func installAllHCLTools(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing all HashiCorp tools")

	if err := installHCLPrerequisites(rc); err != nil {
		return fmt.Errorf("failed to install prerequisites: %w", err)
	}

	if err := installHashiCorpGPGKey(rc); err != nil {
		return fmt.Errorf("failed to install HashiCorp GPG key: %w", err)
	}

	if err := addHashiCorpRepository(rc); err != nil {
		return fmt.Errorf("failed to add HashiCorp repository: %w", err)
	}

	for _, tool := range SupportedHCLTools {
		logger.Info("Installing tool", zap.String("tool", tool))
		
		if err := installSpecificHCLTool(rc, tool); err != nil {
			logger.Error("Failed to install tool", zap.String("tool", tool), zap.Error(err))
			return fmt.Errorf("failed to install %s: %w", tool, err)
		}

		if err := verifyHCLInstallation(rc, tool); err != nil {
			logger.Error("Failed to verify tool installation", zap.String("tool", tool), zap.Error(err))
			return fmt.Errorf("failed to verify %s installation: %w", tool, err)
		}
	}

	logger.Info("Successfully installed all HashiCorp tools")
	return nil
}

func isHCLToolSupported(tool string) bool {
	for _, supported := range SupportedHCLTools {
		if tool == supported {
			return true
		}
	}
	return false
}

func installHCLPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing prerequisites")

	cmd := exec.CommandContext(rc.Ctx, "sudo", "apt-get", "update")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update package list: %w", err)
	}

	cmd = exec.CommandContext(rc.Ctx, "sudo", "apt-get", "install", "-y", "gnupg", "software-properties-common", "curl")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install prerequisites: %w", err)
	}

	return nil
}

func installHashiCorpGPGKey(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing HashiCorp GPG key")

	cmd := exec.CommandContext(rc.Ctx, "bash", "-c", 
		"wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg > /dev/null")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to download and install GPG key: %w", err)
	}

	cmd = exec.CommandContext(rc.Ctx, "gpg", "--no-default-keyring", 
		"--keyring", "/usr/share/keyrings/hashicorp-archive-keyring.gpg", 
		"--fingerprint")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to verify GPG key: %w", err)
	}

	if !strings.Contains(string(output), "HashiCorp Security") {
		return fmt.Errorf("GPG key verification failed: HashiCorp Security not found in fingerprint")
	}

	logger.Info("HashiCorp GPG key verified successfully")
	return nil
}

func addHashiCorpRepository(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Adding HashiCorp repository")

	cmd := exec.CommandContext(rc.Ctx, "bash", "-c", 
		`echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(grep -oP '(?<=UBUNTU_CODENAME=).*' /etc/os-release || lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list`)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add HashiCorp repository: %w", err)
	}

	cmd = exec.CommandContext(rc.Ctx, "sudo", "apt", "update")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update package information: %w", err)
	}

	return nil
}

func installSpecificHCLTool(rc *eos_io.RuntimeContext, tool string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing specific tool", zap.String("tool", tool))

	cmd := exec.CommandContext(rc.Ctx, "sudo", "apt-get", "install", "-y", tool)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install %s: %w", tool, err)
	}

	// Install Packer QEMU plugin if installing Packer
	if tool == "packer" {
		logger.Info("Installing Packer QEMU plugin")
		cmd = exec.CommandContext(rc.Ctx, "packer", "plugins", "install", "github.com/hashicorp/qemu")
		if err := cmd.Run(); err != nil {
			logger.Warn("Failed to install Packer QEMU plugin", zap.Error(err))
			// Don't fail the entire installation if plugin installation fails
		} else {
			logger.Info("Packer QEMU plugin installed successfully")
		}
	}

	return nil
}

func verifyHCLInstallation(rc *eos_io.RuntimeContext, tool string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying installation", zap.String("tool", tool))

	cmd := exec.CommandContext(rc.Ctx, tool, "-help")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to verify %s installation: %w", tool, err)
	}

	helpOutput := string(output)
	if !strings.Contains(helpOutput, "Usage:") {
		return fmt.Errorf("%s installation verification failed: unexpected help output", tool)
	}

	logger.Info("Installation verified successfully", 
		zap.String("tool", tool),
		zap.String("version_check", "passed"))
	
	return nil
}