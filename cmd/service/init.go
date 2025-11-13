package service

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/internal/service"
	eos_cli "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// InitCmd executes the initialization routine for a service definition.
var InitCmd = &cobra.Command{
	Use:   "init <service>",
	Short: "Initialize a service using its declarative definition",
	Long: `Initializes a service by loading its declarative definition, validating
its structure, and preparing the execution environment. Full execution of the
defined steps is still under construction; for now this command validates the
definition and surfaces metadata so operators can confirm readiness.`,
	Args: cobra.ExactArgs(1),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := rc.Log
		serviceName := args[0]

		def, err := service.LoadDefinition(serviceName)
		if err != nil {
			return err
		}

		resume, _ := cmd.Flags().GetBool("resume")
		force, _ := cmd.Flags().GetBool("force")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		logger.Info("Service definition loaded",
			zap.String("service", def.Name),
			zap.Int("steps", len(def.Initialization.Steps)),
			zap.Int("required_variables", len(def.Variables.Required)),
			zap.Bool("resume", resume),
			zap.Bool("force", force),
			zap.Bool("dry_run", dryRun),
		)

		cmd.Println(renderInitSummary(def))
		cmd.Println("Warning: execution engine not yet available; see ROADMAP.md for schedule.")
		return nil
	}),
}

func renderInitSummary(def *service.ServiceDefinition) string {
	var lines []string
	lines = append(lines,
		fmt.Sprintf("Service: %s (version %s)", def.Name, def.Version),
		fmt.Sprintf("Steps:   %d", len(def.Initialization.Steps)),
	)

	if len(def.Dependencies.Containers) > 0 {
		lines = append(lines, fmt.Sprintf("Containers: %s", joinStrings(def.Dependencies.Containers)))
	}
	if len(def.Dependencies.Commands) > 0 {
		lines = append(lines, fmt.Sprintf("Commands:   %s", joinStrings(def.Dependencies.Commands)))
	}
	if len(def.Variables.Required) > 0 {
		lines = append(lines, fmt.Sprintf("Requires variables: %s", joinStrings(def.Variables.Required)))
	}

	if def.HealthCheck.Type != "" {
		lines = append(lines, fmt.Sprintf("Health check: %s", def.HealthCheck.Type))
	}

	return strings.Join(lines, "\n")
}

func joinStrings(items []string) string {
	return strings.Join(items, ", ")
}

func init() {
	InitCmd.Flags().Bool("resume", false, "Resume execution from the last successful step")
	InitCmd.Flags().Bool("force", false, "Reset service state before executing")
	InitCmd.Flags().Bool("dry-run", false, "Validate only; do not execute steps")
}
