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
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh_mssp"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	// Re-registration flags
	reRegister         bool
	analyzeOnly        bool
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
	Short: "Analyze and re-register Wazuh agents with comprehensive checks",
	Long: `Analyze and re-register Wazuh agents with comprehensive checks and transparency.

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
  # Analyze all agents (no changes made)
  eos update wazuh-agents --analyze-only --all-agents

  # Re-register all agents with new manager after analysis
  eos update wazuh-agents --re-register --manager delphi.cybermonkey.net.au --all-agents

  # Re-register specific agents with analysis
  eos update wazuh-agents --re-register --manager delphi.cybermonkey.net.au --agents "001,002,003"

  # Dry run to see analysis and what would happen
  eos update wazuh-agents --re-register --manager delphi.cybermonkey.net.au --all-agents --dry-run

  # Use custom ports and password authentication
  eos update wazuh-agents --re-register --manager delphi.cybermonkey.net.au --all-agents \
    --manager-port 1514 --auth-port 1515 --use-password --password "mypassword"

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

		if !reRegister && !analyzeOnly {
			return fmt.Errorf("either --re-register or --analyze-only flag is required")
		}

		if reRegister && analyzeOnly {
			return fmt.Errorf("cannot use both --re-register and --analyze-only flags together")
		}

		// Validate manager host requirement for re-registration
		if reRegister && managerHost == "" {
			return fmt.Errorf("--manager flag is required when using --re-register")
		}

		// Build configuration from flags
		config := wazuh_mssp.GetDefaultAgentRegistrationConfig()
		config.ManagerHost = managerHost
		config.ManagerPort = managerPort
		config.AuthPort = authPort
		config.AllAgents = allAgents
		config.UsePassword = useWazuhPassword
		config.Password = wazuhPassword
		config.DryRun = wazuhDryRun
		config.BackupKeys = backupKeys
		config.ConcurrentLimit = concurrent

		// Parse target agents if specified
		if targetAgents != "" {
			config.TargetAgents = strings.Split(strings.ReplaceAll(targetAgents, " ", ""), ",")
		}

		// For analyze-only mode, we don't need manager host
		if analyzeOnly {
			config.ManagerHost = "analysis-mode" // Placeholder for validation
			config.DryRun = true // Analysis is always dry-run
		}

		// Validate configuration
		if err := config.Validate(); err != nil {
			return fmt.Errorf("invalid configuration: %v", err)
		}

		// Interactive confirmation for non-dry-run operations
		if !config.DryRun && !analyzeOnly {
			confirmed := interaction.PromptYesNo(rc.Ctx, 
				fmt.Sprintf("Re-register agents with manager %s?", config.ManagerHost), false)
			if !confirmed {
				logger.Info("Operation cancelled by user")
				return nil
			}
		}

		if analyzeOnly {
			logger.Info("🔍 Starting Wazuh agent analysis",
				zap.Bool("all_agents", config.AllAgents))
		} else {
			logger.Info("🚀 Starting Wazuh agent re-registration",
				zap.String("manager_host", config.ManagerHost),
				zap.Bool("all_agents", config.AllAgents),
				zap.Bool("dry_run", config.DryRun))
		}

		// Create registration manager
		manager := wazuh_mssp.NewAgentRegistrationManager(config)

		// Discover agents
		agents, err := manager.DiscoverAgents(rc)
		if err != nil {
			return fmt.Errorf("failed to discover agents: %v", err)
		}

		if len(agents) == 0 {
			logger.Info("No agents found for re-registration")
			return nil
		}

		logger.Info("Discovered agents for re-registration",
			zap.Int("agent_count", len(agents)))

		// Perform re-registration
		summary, err := manager.ReregisterAgents(rc, agents)
		if err != nil {
			return fmt.Errorf("re-registration failed: %v", err)
		}

		// Display results
		fmt.Println(summary.FormatSummary())

		if config.DryRun {
			fmt.Println("\n📋 Generated Re-registration Commands:")
			fmt.Println("Copy and execute these commands on each agent:")
			fmt.Println(strings.Repeat("=", 60))
			
			// Show sample commands for the first agent
			if len(agents) > 0 {
				sampleCommands := manager.GenerateReregistrationCommands(agents[0])
				for _, cmd := range sampleCommands {
					fmt.Println(cmd)
				}
			}
		}

		// Return error if any agents failed (for non-dry-run operations)
		if !config.DryRun && summary.FailureCount > 0 {
			return fmt.Errorf("%d agents failed to re-register", summary.FailureCount)
		}

		logger.Info("✅ Wazuh agent re-registration completed successfully")
		return nil
	}),
}

func init() {
	// Mode selection flags
	updateWazuhAgentsCmd.Flags().BoolVar(&reRegister, "re-register", false,
		"Enable agent re-registration mode")
	updateWazuhAgentsCmd.Flags().BoolVar(&analyzeOnly, "analyze-only", false,
		"Analyze agents without making any changes")

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
