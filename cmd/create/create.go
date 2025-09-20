// cmd/create/create.go

package create

import (
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// CreateCmd is the root command for create operations
var CreateCmd = &cobra.Command{
	Use:     "create",
	Aliases: []string{"deploy", "install", "setup", "add", "c"},
	Short:   "Create, deploy, install resources programmes and components (e.g., processes, users, storage, application containers)",
	Long: `The create command allows you to create various resources such as processes, users, or storage, components or dependencies.
For example:
	eos create trivy 
	eos create vault
	eos create umami
	eos create hecate`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

// log is a package-level variable for the Zap logger.

func init() {
	// Initialize the shared logger for the entire deploy package
	
	// Add storage and VM management commands
	CreateCmd.AddCommand(storageUdisks2Cmd)
	CreateCmd.AddCommand(vmLibvirtCmd)
	CreateCmd.AddCommand(storageUnifiedCmd)
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// Global flags
var (
	dryRun      bool
	backup      bool
	jsonOutput  bool
	force       bool
	interactive bool
)

// SetupCmd represents the setup command
var SetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "System configuration and setup commands",
	Long: `Setup provides initial system configuration and setup commands.

Use these commands to configure system components, install tools,
and perform initial system hardening and configuration.

Examples:
  eos setup tools               # Install essential system tools
  eos setup ssh-key             # Generate SSH key pair
  eos setup mfa                 # Configure multi-factor authentication
  eos setup --list              # List available setup commands`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// If no subcommand is provided, show help
		return cmd.Help()
	}),
}

func init() {
	// Register SetupCmd as a subcommand of CreateCmd
	CreateCmd.AddCommand(SetupCmd)

	// Add global flags
	SetupCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Simulate setup without making changes")
	SetupCmd.PersistentFlags().BoolVarP(&force, "force", "f", false, "Force setup even if already configured")
	SetupCmd.PersistentFlags().BoolVarP(&interactive, "interactive", "i", false, "Interactive setup mode")
	SetupCmd.PersistentFlags().BoolVar(&backup, "backup", true, "Create backup before making changes")
	SetupCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
}

