// cmd/create/cloudinit.go
package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/cloudinit"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var cloudInitCmd = &cobra.Command{
	Use:   "cloudinit",
	Short: "Generate cloud-init configuration",
	Long: `Generate cloud-init YAML configuration based on current system state.
	
This command analyzes the current system (hostname, user, SSH keys, installed packages)
and generates a cloud-init configuration file that can be used to replicate this
system setup on cloud instances.`,
	RunE: eos_cli.Wrap(runCreateCloudInit),
}

var (
	outputPath   string
	templateMode bool
)

func init() {
	CreateCmd.AddCommand(cloudInitCmd)

	cloudInitCmd.Flags().StringVarP(&outputPath, "output", "o", "/etc/cloud/cloud.cfg.d/99-eos-config.yaml",
		"Output path for the cloud-init configuration")
	cloudInitCmd.Flags().BoolVarP(&templateMode, "template", "t", false,
		"Generate a template instead of system-specific configuration")
}

func runCreateCloudInit(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating cloud-init configuration")

	generator := cloudinit.NewGenerator(rc)

	// Generate template if requested
	if templateMode {
		logger.Info("Generating cloud-init template", zap.String("output", outputPath))
		if err := generator.GenerateTemplate(outputPath); err != nil {
			return fmt.Errorf("failed to generate template: %w", err)
		}
		return nil
	}

	// Gather system information
	logger.Info("Gathering system information")
	info, err := generator.GatherSystemInfo()
	if err != nil {
		return fmt.Errorf("failed to gather system info: %w", err)
	}

	logger.Info("System information gathered",
		zap.String("hostname", info.Hostname),
		zap.String("username", info.Username),
		zap.Int("packages", len(info.InstalledPackages)),
		zap.Bool("ssh_key_found", info.SSHPublicKey != ""))

	// Generate configuration
	config, err := generator.GenerateConfig(info)
	if err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}

	// Validate configuration
	if err := generator.ValidateConfig(config); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// Write configuration
	if err := generator.WriteConfig(config, outputPath); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	logger.Info("Cloud-init configuration generated successfully",
		zap.String("output", outputPath),
		zap.String("hostname", config.Hostname),
		zap.Int("users", len(config.Users)),
		zap.Int("packages", len(config.Packages)))

	fmt.Printf("\n✅ Cloud-init configuration generated successfully!\n")
	fmt.Printf("📁 Output: %s\n", outputPath)
	fmt.Printf("🖥️  Hostname: %s\n", config.Hostname)
	fmt.Printf("👤 User: %s\n", info.Username)
	fmt.Printf("📦 Packages: %d\n", len(config.Packages))

	if info.SSHPublicKey != "" {
		fmt.Printf("🔑 SSH Key: Configured\n")
	} else {
		fmt.Printf("⚠️  SSH Key: Not found - manual configuration needed\n")
	}

	return nil
}