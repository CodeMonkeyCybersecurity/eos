// cmd/create/tailscale.go
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/infrastructure/network"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/service_installation"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Flag variables for Tailscale hosts command
var (
	hostsOutputFile      string
	hostsFormat          string
	hostsExcludeOffline  bool
	hostsExcludeSelf     bool
	hostsIncludeComments bool
	hostsFilterHosts     []string
	generateAnsible      bool
)

// CreateTailscaleCmd installs Tailscale VPN
var CreateTailscaleCmd = &cobra.Command{
	Use:   "tailscale",
	Short: "Install Tailscale VPN",
	Long: `Install Tailscale for secure networking and VPN connectivity.

Tailscale is a zero-config VPN that creates a secure network between your devices.
It uses WireGuard for encryption and works seamlessly across platforms.

Examples:
  eos create tailscale              # Install Tailscale
  eos create tailscale --dry-run    # Test installation`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		autoStart, _ := cmd.Flags().GetBool("auto-start")

		logger.Info("Installing Tailscale",
			zap.Bool("dry_run", dryRun),
			zap.Bool("auto_start", autoStart))

		manager := service_installation.NewServiceInstallationManager()

		// Build installation options
		options := &service_installation.ServiceInstallOptions{
			Name:        "tailscale",
			Type:        service_installation.ServiceTypeTailscale,
			Method:      service_installation.MethodNative,
			DryRun:      dryRun,
			Environment: make(map[string]string),
			Config:      make(map[string]string),
		}

		if autoStart {
			options.Config["auto_start"] = "true"
		}

		// Perform installation
		result, err := manager.InstallService(rc, options)
		if err != nil {
			return fmt.Errorf("tailscale installation failed: %w", err)
		}

		// Output result
		if result.Success {
			logger.Info("Tailscale installation completed successfully",
				zap.Duration("duration", result.Duration))

			fmt.Printf("\nTailscale Installation Complete!\n\n")
			fmt.Printf(" Service Details:\n")
			fmt.Printf("   Method: %s\n", result.Method)
			fmt.Printf("   Duration: %s\n", result.Duration)

			if result.Version != "" {
				fmt.Printf("   Version: %s\n", result.Version)
			}

			fmt.Printf("\n📝 Next Steps:\n")
			fmt.Printf("   1. Authenticate: sudo tailscale up\n")
			fmt.Printf("   2. Check status: tailscale status\n")
			fmt.Printf("   3. View IP: tailscale ip -4\n")
			fmt.Printf("   4. Manage at: https://login.tailscale.com/admin\n")

			fmt.Printf("\n💡 Tips:\n")
			fmt.Printf("   - Use 'tailscale up --ssh' to enable SSH access\n")
			fmt.Printf("   - Use 'tailscale up --advertise-routes=192.168.1.0/24' to share local networks\n")
			fmt.Printf("   - Check service: eos status tailscale\n")
		} else {
			logger.Error("Tailscale installation failed", zap.String("error", result.Error))
			fmt.Printf("\n❌ Tailscale Installation Failed!\n")
			fmt.Printf("Error: %s\n", result.Error)

			if len(result.Steps) > 0 {
				fmt.Printf("\nInstallation Steps:\n")
				for _, step := range result.Steps {
					status := ""
					if step.Status == "failed" {
						status = "❌"
					} else if step.Status == "running" {
						status = "⏳"
					}
					fmt.Printf("   %s %s (%s)\n", status, step.Name, step.Duration)
					if step.Error != "" {
						fmt.Printf("      Error: %s\n", step.Error)
					}
				}
			}
		}

		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateTailscaleCmd)

	CreateTailscaleCmd.Flags().Bool("dry-run", false, "Simulate installation without making changes")
	CreateTailscaleCmd.Flags().Bool("auto-start", false, "Automatically start Tailscale after installation")
}

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
		return network.RunCreateTailscaleHosts(rc, cmd, args)
	}),
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
