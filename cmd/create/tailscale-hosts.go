package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/infrastructure/network"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	hostsOutputFile      string
	hostsFormat          string
	hostsExcludeOffline  bool
	hostsExcludeSelf     bool
	hostsIncludeComments bool
	hostsFilterHosts     []string
	generateAnsible      bool
)

// CreateTailscaleHostsCmd represents the create tailscale-hosts command
var CreateTailscaleHostsCmd = &cobra.Command{
	Use:   "tailscale-hosts",
	Short: "Generate hosts configuration from Tailscale network",
	Long: `Generate hosts configuration files from the current Tailscale network status.
This command retrieves the list of peers from Tailscale and creates configuration
files in various formats for use with other tools.

Supported formats:
- yaml: YAML format for configuration management
- json: JSON format for programmatic use
- conf: Simple configuration format
- hosts: /etc/hosts file format
- ansible: Ansible inventory format

Examples:
  eos create tailscale-hosts                              # Generate YAML to default location
  eos create tailscale-hosts --format json                # Generate JSON format
  eos create tailscale-hosts --output /etc/hosts.tailscale # Save to specific file
  eos create tailscale-hosts --exclude-offline            # Exclude offline peers
  eos create tailscale-hosts --ansible                    # Generate Ansible inventory`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return runCreateTailscaleHosts(rc, cmd, args)
	}),
}

func runCreateTailscaleHosts(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating Tailscale hosts configuration")

	// Handle Ansible inventory generation
	if generateAnsible {
		outputFile := hostsOutputFile
		if outputFile == "" {
			outputFile = "/tmp/tailscale_inventory.ini"
		}
		return network.GetTailscaleHostsForAnsible(rc, outputFile)
	}

	// Create configuration
	config := &network.HostsConfig{
		OutputFile:      hostsOutputFile,
		Format:          hostsFormat,
		ExcludeOffline:  hostsExcludeOffline,
		ExcludeSelf:     hostsExcludeSelf,
		IncludeComments: hostsIncludeComments,
		FilterHosts:     hostsFilterHosts,
	}

	// Generate hosts configuration
	if err := network.GenerateTailscaleHostsConfig(rc, config); err != nil {
		logger.Error("Failed to generate Tailscale hosts configuration", zap.Error(err))
		return err
	}

	logger.Info("Tailscale hosts configuration generated successfully",
		zap.String("output_file", config.OutputFile),
		zap.String("format", config.Format))

	return nil
}

func init() {
	CreateCmd.AddCommand(CreateTailscaleHostsCmd)

	CreateTailscaleHostsCmd.Flags().StringVar(&hostsOutputFile, "output", "", "Output file path (default: /tmp/tailscale_hosts.conf)")
	CreateTailscaleHostsCmd.Flags().StringVar(&hostsFormat, "format", "yaml", "Output format (yaml, json, conf, hosts)")
	CreateTailscaleHostsCmd.Flags().BoolVar(&hostsExcludeOffline, "exclude-offline", false, "Exclude offline peers")
	CreateTailscaleHostsCmd.Flags().BoolVar(&hostsExcludeSelf, "exclude-self", true, "Exclude self from the list")
	CreateTailscaleHostsCmd.Flags().BoolVar(&hostsIncludeComments, "include-comments", true, "Include comments in output")
	CreateTailscaleHostsCmd.Flags().StringSliceVar(&hostsFilterHosts, "filter-hosts", []string{}, "Only include hosts matching these patterns")
	CreateTailscaleHostsCmd.Flags().BoolVar(&generateAnsible, "ansible", false, "Generate Ansible inventory format")
}