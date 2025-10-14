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
	Aliases: []string{"build", "deploy", "install", "setup", "add", "c"},
	Short:   "Create, build, deploy, install resources programmes and components (e.g., processes, users, storage, application containers)",
	Long: `The create command allows you to create various resources such as processes, users, or storage, components or dependencies.

Aliases:
  eos create  = eos build   (build applications and components)
  eos create  = eos deploy  (deploy applications and services)

For example:
	eos create trivy
	eos create vault
	eos create umami
	eos create hecate

	eos build --all          (alias for creating/building all components)
	eos deploy app helen     (alias for creating/deploying applications)`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

// buildCmd represents the build subcommand under create
// This allows 'eos build' to work as an alias for 'eos create build'
var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build applications and components",
	Long: `Build applications and components using the Eos CI/CD system.

The build system follows the assessment→intervention→evaluation pattern to ensure
reliable builds across different environments and components. It supports parallel
builds, dependency resolution, and artifact management.

Build operations include:
- Component compilation and packaging
- Docker image creation and tagging
- Artifact validation and testing
- Dependency resolution and caching
- Build artifact storage and metadata

Examples:
  # Build all components
  eos build --all

  # Build specific component
  eos build helen

  # Build with custom tag
  eos build helen --tag v2.1.0

  # Parallel build with dependencies
  eos build --all --parallel --with-dependencies`,
	Aliases: []string{"compile", "make"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("Build command not yet implemented")
		return cmd.Help()
	}),
}

// deployCmd represents the deploy subcommand under create
// This allows 'eos deploy' to work as an alias for 'eos create deploy'
var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy applications and services to various environments",
	Long: `Deploy applications and services with advanced deployment strategies and comprehensive
orchestration following the Consul → Terraform → Nomad hierarchy.

The deployment system provides sophisticated deployment strategies, progressive rollouts,
comprehensive health checking, and automated rollback capabilities. All deployments follow
the assessment→intervention→evaluation pattern to ensure reliable and safe deployments.

Deployment features include:
- Multiple deployment strategies (rolling, blue-green, canary, immutable)
- Environment-aware deployments with validation and approval workflows
- Comprehensive health checking and smoke testing
- Automated rollback on failure with configurable thresholds
- Integration with HashiCorp stack (Nomad, Consul, Vault)
- Real-time deployment monitoring and progress tracking
- Deployment history and audit trails

Deployment Strategies:
  rolling      Rolling deployment with configurable batch sizes
  blue-green   Blue-green deployment with traffic switching
  canary       Canary deployment with gradual traffic shifting
  immutable    Immutable infrastructure replacement

Examples:
  # Rolling deployment to staging
  eos deploy app helen --environment staging

  # Blue-green deployment to production
  eos deploy app helen --environment production --strategy blue-green

  # Canary deployment with 10% initial traffic
  eos deploy app api --environment production --strategy canary --canary-percentage 10

  # Deploy entire stack
  eos deploy stack webapp --environment staging`,
	Aliases: []string{"deployment"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("Deploy command not yet implemented")
		return cmd.Help()
	}),
}

// log is a package-level variable for the Zap logger.

func init() {
	// Add storage and VM management commands
	CreateCmd.AddCommand(storageUdisks2Cmd)
	CreateCmd.AddCommand(vmLibvirtCmd)
	CreateCmd.AddCommand(storageUnifiedCmd)

	// Add build and deploy as subcommands of create
	// This enables both 'eos create build' and 'eos build' (via alias)
	CreateCmd.AddCommand(buildCmd)
	CreateCmd.AddCommand(deployCmd)
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

