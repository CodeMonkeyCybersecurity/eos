// cmd/update/wazuh_agents.go
//
// Wazuh Agent Re-registration Commands
//
// This file implements CLI commands for re-registering Wazuh agents with a new
// Wazuh manager server. This is essential when replacing a Wazuh server due to
// hardware issues, migrations, or infrastructure changes.
//
// Key Features:
// - Automatic agent discovery and re-registration
// - Batch processing for multiple agents
// - Safety checks and validation
// - Integration with existing EOS Wazuh infrastructure
// - Support for different authentication methods
// - Dry-run capabilities for testing
//
// Available Commands:
// - eos update wazuh-agents --re-register --manager delphi.cybermonkey.net.au
// - eos update wazuh-agents --re-register --manager delphi.cybermonkey.net.au --all-agents
// - eos update wazuh-agents --re-register --manager delphi.cybermonkey.net.au --agents agent1,agent2
// - eos update wazuh-agents --re-register --manager delphi.cybermonkey.net.au --dry-run
//
// Use Cases:
// - New Wazuh server deployment (same hostname, different VM)
// - Wazuh server migration or replacement
// - Agent key corruption or authentication issues
// - Bulk agent management operations
//
// Integration:
// This system builds on the existing EOS Wazuh functionality and leverages
// the centralized version management system for consistency.

package update

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var (
	// Operation mode flags
	reRegister         bool
	analyzeOnly        bool
	forceUpgrade       bool
	
	// Configuration flags
	managerHost        string
	managerPort        int
	authPort           int
	targetAgents       string
	allAgents          bool
	useWazuhPassword   bool
	wazuhPassword      string
	wazuhDryRun        bool
	backupKeys         bool
	concurrent         int
)

var updateWazuhAgentsCmd = &cobra.Command{
	Use:   "wazuh-agents",
	Short: "Upgrade local Wazuh agent with comprehensive analysis and safety checks",
	Long: `Upgrade the local Wazuh agent with comprehensive analysis and safety checks.

This command provides robust analysis and management of Wazuh agents, following EOS 
principles of transparency and safety. It performs comprehensive checks including:
- Current version detection and comparison with latest available
- Platform and architecture identification  
- Repository connectivity validation
- Upgrade path analysis and risk assessment
- Prerequisites verification

The command will:
1. Discover existing Wazuh agents via Delphi API
2. Perform comprehensive analysis of each agent
3. Generate platform-specific upgrade/re-registration commands
4. Provide detailed status, recommendations, and results
5. Optionally execute the re-registration process

Examples:
  # Default: Upgrade local Wazuh agent (with comprehensive analysis)
  eos update wazuh-agents

  # Analyze local agent without making changes
  eos update wazuh-agents --analyze-only

  # Upgrade with dry-run to see what would happen
  eos update wazuh-agents --dry-run

  # Upgrade and re-register with new manager
  eos update wazuh-agents --manager delphi.cybermonkey.net.au

  # Re-register only (no upgrade)
  eos update wazuh-agents --re-register --manager delphi.cybermonkey.net.au

  # Force upgrade even if already current
  eos update wazuh-agents --force-upgrade

Analysis Features:
  - Version comparison (current vs latest available)
  - Platform detection (Ubuntu, CentOS, macOS, Windows)
  - Repository connectivity validation
  - Upgrade method determination (apt, yum, pkg, msi)
  - Risk assessment (low, medium, high)
  - Prerequisites and duration estimation

Common Use Cases:
  - New Wazuh server deployment (same hostname, different VM)
  - Wazuh server migration or replacement  
  - Agent version analysis and upgrade planning
  - Repository connectivity troubleshooting
  - Agent key corruption or authentication issues
  - Bulk agent management operations`,

	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Build configuration for agent upgrade (default action)
		config := delphi.GetDefaultAgentUpgradeConfig()
		
		// Determine operation mode
		if reRegister {
			config.UpgradeAgent = false
			config.ReRegisterOnly = true
			
			// Validate manager host requirement for re-registration
			if managerHost == "" {
				return fmt.Errorf("--manager flag is required when using --re-register")
			}
			config.ManagerHost = managerHost
		} else if analyzeOnly {
			config.UpgradeAgent = false
			config.AnalyzeOnly = true
		} else {
			// Default: upgrade agent
			config.UpgradeAgent = true
			if managerHost != "" {
				config.ManagerHost = managerHost // Optional re-registration after upgrade
			}
		}

		// Apply other configuration
		config.ManagerPort = managerPort
		config.AuthPort = authPort
		config.UsePassword = useWazuhPassword
		config.Password = wazuhPassword
		config.DryRun = wazuhDryRun
		config.BackupKeys = backupKeys
		config.ForceUpgrade = forceUpgrade

		// Interactive confirmation for non-dry-run operations
		if !config.DryRun && !config.AnalyzeOnly {
			var confirmMsg string
			if config.UpgradeAgent {
				confirmMsg = "Upgrade local Wazuh agent?"
			} else {
				confirmMsg = fmt.Sprintf("Re-register agent with manager %s?", config.ManagerHost)
			}
			
			confirmed := interaction.PromptYesNo(rc.Ctx, confirmMsg, false)
			if !confirmed {
				logger.Info("Operation cancelled by user")
				return nil
			}
		}

		// Create upgrade manager
		upgradeManager := delphi.NewAgentUpgradeManager(config)

		// Execute the operation
		result, err := upgradeManager.UpgradeLocalAgent(rc)
		if err != nil {
			return fmt.Errorf("operation failed: %v", err)
		}

		// Display results
		if result.Analysis != nil {
			fmt.Printf("\n📊 Agent Analysis Results:\n")
			fmt.Printf("Current Version: %s\n", result.Analysis.CurrentVersion)
			fmt.Printf("Latest Version: %s\n", result.Analysis.LatestVersion)
			fmt.Printf("Platform: %s (%s)\n", result.Analysis.Platform, result.Analysis.Architecture)
			fmt.Printf("Needs Upgrade: %t\n", result.Analysis.NeedsUpgrade)
			fmt.Printf("Upgrade Method: %s\n", result.Analysis.UpgradeMethod)
			fmt.Printf("Risk Level: %s\n", result.Analysis.RiskLevel)
			fmt.Printf("Repository Reachable: %t\n", result.Analysis.RepositoryReachable)
			
			if len(result.Analysis.ConnectivityIssues) > 0 {
				fmt.Printf("\n⚠️  Connectivity Issues:\n")
				for _, issue := range result.Analysis.ConnectivityIssues {
					fmt.Printf("  - %s\n", issue)
				}
			}
			
			if len(result.Analysis.Prerequisites) > 0 {
				fmt.Printf("\n📋 Prerequisites:\n")
				for _, prereq := range result.Analysis.Prerequisites {
					fmt.Printf("  - %s\n", prereq)
				}
			}
		}

		if result.Success {
			if config.AnalyzeOnly {
				fmt.Printf("\n✅ Analysis completed successfully\n")
			} else if config.UpgradeAgent {
				fmt.Printf("\n✅ Agent upgrade completed successfully in %v\n", result.Duration)
			} else {
				fmt.Printf("\n✅ Agent re-registration completed successfully in %v\n", result.Duration)
			}
		} else {
			fmt.Printf("\n❌ Operation failed: %s\n", result.Error)
			return fmt.Errorf("operation failed: %s", result.Error)
		}

		return nil
	}),
}

func init() {
	// Mode selection flags
	updateWazuhAgentsCmd.Flags().BoolVar(&reRegister, "re-register", false,
		"Enable agent re-registration mode (instead of upgrade)")
	updateWazuhAgentsCmd.Flags().BoolVar(&analyzeOnly, "analyze-only", false,
		"Analyze agent without making any changes")
	updateWazuhAgentsCmd.Flags().BoolVar(&forceUpgrade, "force-upgrade", false,
		"Force upgrade even if agent is already current")

	// Manager configuration flags
	updateWazuhAgentsCmd.Flags().StringVar(&managerHost, "manager", "",
		"Wazuh manager hostname or IP address (required for re-registration)")
	updateWazuhAgentsCmd.Flags().IntVar(&managerPort, "manager-port", 1514,
		"Wazuh manager port")
	updateWazuhAgentsCmd.Flags().IntVar(&authPort, "auth-port", 1515,
		"Wazuh agent authentication port")

	// Agent selection flags
	updateWazuhAgentsCmd.Flags().StringVar(&targetAgents, "agents", "",
		"Comma-separated list of agent IDs to re-register")
	updateWazuhAgentsCmd.Flags().BoolVar(&allAgents, "all-agents", false,
		"Re-register all discovered agents")

	// Authentication flags
	updateWazuhAgentsCmd.Flags().BoolVar(&useWazuhPassword, "use-password", false,
		"Use password authentication for agent registration")
	updateWazuhAgentsCmd.Flags().StringVar(&wazuhPassword, "password", "",
		"Password for agent authentication (if required)")

	// Operation flags
	updateWazuhAgentsCmd.Flags().BoolVar(&wazuhDryRun, "dry-run", false,
		"Show what would be done without executing")
	updateWazuhAgentsCmd.Flags().BoolVar(&backupKeys, "backup-keys", true,
		"Backup existing client keys before re-registration")
	updateWazuhAgentsCmd.Flags().IntVar(&concurrent, "concurrent", 5,
		"Maximum number of concurrent re-registrations")

	// Manager is only required for re-registration mode
	// This will be validated in the command logic instead of marking as required

	// Add to parent command
	UpdateCmd.AddCommand(updateWazuhAgentsCmd)
}
