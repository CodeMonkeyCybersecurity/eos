// cmd/create/cloudinit.go
package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/cloudinit"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/spf13/cobra"
)

var cloudInitCmd = &cobra.Command{
	Use:   "cloudinit",
	Short: "Generate cloud-init configuration",
	Long: `Generate cloud-init YAML configuration based on current system state.
	
This command analyzes the current system (hostname, user, SSH keys, installed packages)
and generates a cloud-init configuration file that can be used to replicate this
system setup on cloud instances.`,
	RunE: eos_cli.Wrap(cloudinit.RunCreateCloudInit),
}

func init() {
	CreateCmd.AddCommand(cloudInitCmd)

	cloudInitCmd.Flags().StringVarP(&cloudinit.OutputPath, "output", "o", "/etc/cloud/cloud.cfg.d/99-eos-config.yaml",
		"Output path for the cloud-init configuration")
	cloudInitCmd.Flags().BoolVarP(&cloudinit.TemplateMode, "template", "t", false,
		"Generate a template instead of system-specific configuration")
}
