// cmd/delphi/services/services.go
package services

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServicesCmd represents the 'services' command for managing Delphi pipeline services
var ServicesCmd = &cobra.Command{
	Use:   "services",
	Short: "Manage Delphi pipeline systemd services",
	Long: `The 'services' command provides CRUD operations and management for Delphi data pipeline systemd services.

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service
- llm-worker: LLM processing service
- prompt-ab-tester: A/B testing worker for prompt optimization

CRUD Operations:
- create <service>: Deploy/install a service with all required files
- read <service>: Display detailed service information and configuration
- update <service>: Update service workers and configuration to latest version
- delete <service>: Remove service files (preserves configuration/data)
- list: Show all services and their status

Service Management:
- start/stop/restart: Control service lifecycle
- enable/disable: Configure service autostart
- status: View service status and health
- logs: View service logs and troubleshooting info
- cleanup: Detect and fix zombie services (running without unit files)

Special Operations:
- deploy-ab-config: Deploy A/B testing configuration for prompt optimization
- analyze-ab-results: Analyze A/B testing results and provide optimization insights`,
	Aliases: []string{"svc"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Services command called without subcommand",
			zap.String("command", "eos delphi services"),
		)
		shared.SafeHelp(cmd)
		return nil
	}),
}

func init() {
	// CRUD operations (primary interface)
	ServicesCmd.AddCommand(NewCreateCmd())
	ServicesCmd.AddCommand(NewReadCmd())
	ServicesCmd.AddCommand(NewUpdateCmd())
	ServicesCmd.AddCommand(NewDeleteCmd())
	ServicesCmd.AddCommand(NewListCmd())
	
	// Service management operations
	ServicesCmd.AddCommand(NewStartCmd())
	ServicesCmd.AddCommand(NewStopCmd())
	ServicesCmd.AddCommand(NewRestartCmd())
	ServicesCmd.AddCommand(NewStatusCmd())
	ServicesCmd.AddCommand(NewEnableCmd())
	ServicesCmd.AddCommand(NewDisableCmd())
	ServicesCmd.AddCommand(NewLogsCmd())
	ServicesCmd.AddCommand(NewCleanupCmd()) // Zombie service cleanup
	
	// Special operations
	// Note: checkCmd and installCmd add themselves via their own init() functions
	ServicesCmd.AddCommand(NewDeployABConfigCmd())
	ServicesCmd.AddCommand(NewAnalyzeABResultsCmd())
	ServicesCmd.AddCommand(NewABConfigCmd())  // Enhanced A/B testing management
}