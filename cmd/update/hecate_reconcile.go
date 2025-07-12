package update

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/temporal"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var updateHecateReconcileCmd = &cobra.Command{
	Use:   "reconcile",
	Short: "Reconcile Hecate state with desired configuration",
	Long: `Reconcile compares the desired state (from Git/Consul) with the current 
runtime state (in Caddy/Authentik) and applies any necessary changes to bring 
the runtime state in line with the desired state.

This command supports:
- Dry-run mode to preview changes
- Component-specific reconciliation
- Force mode to override locks
- Multiple state sources (Git, Consul)

Examples:
  eos update hecate reconcile --component all --dry-run
  eos update hecate reconcile --component routes
  eos update hecate reconcile --component auth --force
  eos update hecate reconcile --source git --repository https://github.com/org/config`,
	RunE: eos_cli.Wrap(runUpdateHecateReconcile),
}

func init() {
	updateHecateCmd.AddCommand(updateHecateReconcileCmd)

	// Define flags
	updateHecateReconcileCmd.Flags().String("component", "all", "Component to reconcile: all, routes, auth, upstreams")
	updateHecateReconcileCmd.Flags().Bool("dry-run", false, "Show what would be changed without applying")
	updateHecateReconcileCmd.Flags().Bool("force", false, "Force reconciliation even if lock cannot be acquired")
	updateHecateReconcileCmd.Flags().String("source", "consul", "State source: git, consul")
	updateHecateReconcileCmd.Flags().String("git-repository", "", "Git repository URL (for git source)")
	updateHecateReconcileCmd.Flags().String("git-branch", "main", "Git branch (for git source)")
	updateHecateReconcileCmd.Flags().String("git-path", "hecate/", "Path in Git repository (for git source)")
	updateHecateReconcileCmd.Flags().StringSlice("caddy-endpoints", []string{"http://localhost:2019"}, "Caddy admin endpoints")
	updateHecateReconcileCmd.Flags().String("authentik-url", "", "Authentik base URL")
}

func runUpdateHecateReconcile(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	component, _ := cmd.Flags().GetString("component")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	force, _ := cmd.Flags().GetBool("force")
	source, _ := cmd.Flags().GetString("source")
	gitRepository, _ := cmd.Flags().GetString("git-repository")
	gitBranch, _ := cmd.Flags().GetString("git-branch")
	gitPath, _ := cmd.Flags().GetString("git-path")
	caddyEndpoints, _ := cmd.Flags().GetStringSlice("caddy-endpoints")
	authentikURL, _ := cmd.Flags().GetString("authentik-url")

	logger.Info("Starting Hecate state reconciliation",
		zap.String("component", component),
		zap.Bool("dry_run", dryRun),
		zap.Bool("force", force),
		zap.String("source", source))

	// Create reconciliation request
	request := temporal.ReconciliationRequest{
		Component:           component,
		DryRun:              dryRun,
		Source:              source,
		GitRepository:       gitRepository,
		GitBranch:           gitBranch,
		GitPath:             gitPath,
		CaddyAdminEndpoints: caddyEndpoints,
		AuthentikURL:        authentikURL,
		Force:               force,
	}

	// Execute reconciliation
	if err := temporal.ReconcileWithEos(rc, request); err != nil {
		return err
	}

	logger.Info("Hecate state reconciliation completed successfully",
		zap.String("component", component))

	return nil
}