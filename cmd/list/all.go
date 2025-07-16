package list

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/state"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "List all eos-managed resources",
	Long: `Display a comprehensive list of all resources managed by eos.
This includes:
- Installed components (Salt, Vault, Nomad, etc.)
- Running services
- Salt states and pillars
- Nomad jobs
- System directories
- Package installations

The command uses both in-band (eos tools) and out-of-band (OSQuery) methods
to gather a complete picture of the infrastructure state.`,
	RunE: eos_cli.Wrap(runListAll),
	Aliases: []string{"--all"},
}

func init() {
	ListCmd.AddCommand(allCmd)
	
	allCmd.Flags().Bool("json", false, "Output in JSON format")
	allCmd.Flags().Bool("verify", false, "Verify component status with OSQuery")
	allCmd.Flags().Bool("detailed", false, "Show detailed information")
}

func runListAll(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	jsonOutput := cmd.Flag("json").Value.String() == "true"
	verify := cmd.Flag("verify").Value.String() == "true"
	detailed := cmd.Flag("detailed").Value.String() == "true"
	
	logger.Info("Gathering comprehensive infrastructure state",
		zap.Bool("json_output", jsonOutput),
		zap.Bool("verify", verify),
		zap.Bool("detailed", detailed))
	
	// Load or create state tracker
	tracker, err := state.Load(rc)
	if err != nil {
		logger.Debug("Creating new state tracker", zap.Error(err))
		tracker = state.New()
	}
	
	// Gather current state
	logger.Info("Gathering in-band state information")
	if err := tracker.GatherInBand(rc); err != nil {
		logger.Warn("Failed to gather complete in-band state", zap.Error(err))
	}
	
	if verify {
		logger.Info("Gathering out-of-band state information via OSQuery")
		if err := tracker.GatherOutOfBand(rc); err != nil {
			logger.Warn("Failed to gather out-of-band state", zap.Error(err))
		}
	}
	
	// Save updated state
	if err := tracker.Save(rc); err != nil {
		logger.Warn("Failed to save updated state", zap.Error(err))
	}
	
	// Output results
	if jsonOutput {
		// TODO: Implement JSON output
		logger.Warn("JSON output not yet implemented")
		return nil
	}
	
	// Text output
	fmt.Println("EOS Infrastructure Overview")
	fmt.Println("===========================")
	fmt.Println()
	
	// Components section
	if len(tracker.Components) > 0 {
		fmt.Println("Installed Components:")
		fmt.Println("--------------------")
		fmt.Printf("%-15s %-20s %-15s %s\n", "TYPE", "NAME", "VERSION", "STATUS")
		fmt.Println(strings.Repeat("-", 70))
		
		for _, comp := range tracker.Components {
			status := comp.Status
			if status == "active" {
				status = "✓ " + status
			} else if status == "inactive" {
				status = "✗ " + status
			}
			
			fmt.Printf("%-15s %-20s %-15s %s\n",
				comp.Type,
				comp.Name,
				comp.Version,
				status)
			
			if detailed && comp.Config != nil {
				fmt.Printf("  Config: %v\n", comp.Config)
			}
		}
		fmt.Println()
	}
	
	// Services section
	if len(tracker.SystemdUnits) > 0 {
		fmt.Println("Systemd Services:")
		fmt.Println("----------------")
		for _, unit := range tracker.SystemdUnits {
			fmt.Printf("  • %s\n", unit)
		}
		fmt.Println()
	}
	
	// Salt section
	if len(tracker.SaltStates) > 0 {
		fmt.Println("Salt States:")
		fmt.Println("-----------")
		for _, state := range tracker.SaltStates {
			fmt.Printf("  • %s\n", state)
		}
		fmt.Println()
	}
	
	// Nomad section
	if len(tracker.NomadJobs) > 0 {
		fmt.Println("Nomad Jobs:")
		fmt.Println("----------")
		for _, job := range tracker.NomadJobs {
			fmt.Printf("  • %s\n", job)
		}
		fmt.Println()
	}
	
	// Directories section
	if len(tracker.Directories) > 0 {
		fmt.Println("EOS Directories:")
		fmt.Println("---------------")
		for _, dir := range tracker.Directories {
			fmt.Printf("  • %s\n", dir)
		}
		fmt.Println()
	}
	
	// Additional checks if detailed
	if detailed {
		cli := eos_cli.New(rc)
		
		// Check for ClusterFuzz
		if _, err := cli.ExecString("ls", "/opt/clusterfuzz"); err == nil {
			fmt.Println("ClusterFuzz:")
			fmt.Println("-----------")
			if output, err := cli.ExecString("find", "/opt/clusterfuzz", "-name", "*.yaml", "-o", "-name", "*.yml"); err == nil {
				lines := strings.Split(strings.TrimSpace(output), "\n")
				for _, line := range lines {
					if line != "" {
						fmt.Printf("  • %s\n", line)
					}
				}
			}
			fmt.Println()
		}
		
		// Port usage
		fmt.Println("Network Ports:")
		fmt.Println("-------------")
		ports := map[string]string{
			"8200": "Vault",
			"4646": "Nomad HTTP",
			"4647": "Nomad RPC",
			"4648": "Nomad Serf",
			"4505": "Salt Master Publish",
			"4506": "Salt Master Ret",
		}
		
		for port, service := range ports {
			if output, err := cli.ExecString("ss", "-tlnp", "sport", "=", ":"+port); err == nil && output != "" {
				fmt.Printf("  • :%s - %s (listening)\n", port, service)
			}
		}
		fmt.Println()
	}
	
	// Summary
	fmt.Println("Summary:")
	fmt.Println("--------")
	fmt.Printf("Components: %d\n", len(tracker.Components))
	fmt.Printf("Services:   %d\n", len(tracker.SystemdUnits))
	fmt.Printf("Salt States: %d\n", len(tracker.SaltStates))
	fmt.Printf("Nomad Jobs: %d\n", len(tracker.NomadJobs))
	fmt.Printf("Directories: %d\n", len(tracker.Directories))
	fmt.Printf("\nLast Updated: %s\n", tracker.LastUpdated.Format("2006-01-02 15:04:05"))
	
	// Quick actions
	fmt.Println("\nQuick Actions:")
	fmt.Println("-------------")
	fmt.Println("• View specific component: eos list [component]")
	fmt.Println("• Update infrastructure:   eos update [component]")
	fmt.Println("• Remove everything:       eos delete nuke --all")
	fmt.Println("• Verify with OSQuery:     eos list all --verify")
	
	return nil
}