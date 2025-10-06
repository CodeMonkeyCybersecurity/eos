package build

import (
	"fmt"
	"sort"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/build"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "Build all components",
	Long: `Build all components in the correct dependency order with parallel execution support.

This command discovers all buildable components in the workspace and builds them
following their dependency graph. It supports parallel execution where dependencies
allow, and provides comprehensive reporting on the build process.

The build orchestration includes:
- Automatic component discovery
- Dependency graph resolution
- Parallel execution optimization
- Build failure handling and rollback
- Comprehensive progress reporting
- Artifact coordination and management

Examples:
  # Build all components sequentially
  eos build all

  # Build all components in parallel where possible
  eos build all --parallel

  # Build with specific tag
  eos build all --tag v2.1.0

  # Build and push all to registry
  eos build all --push --registry registry.cybermonkey.net.au

  # Dry run to see build plan
  eos build all --dry-run --parallel`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("Building all components",
			zap.String("command", "build all"),
			zap.String("context", rc.Component))

		// Parse flags
		tag, _ := cmd.Flags().GetString("tag")
		push, _ := cmd.Flags().GetBool("push")
		registry, _ := cmd.Flags().GetString("registry")
		parallel, _ := cmd.Flags().GetBool("parallel")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force-rebuild")
		filter, _ := cmd.Flags().GetString("filter")
		exclude, _ := cmd.Flags().GetStringSlice("exclude")
		continueOnError, _ := cmd.Flags().GetBool("continue-on-error")

		logger.Debug("Build all configuration",
			zap.String("tag", tag),
			zap.Bool("parallel", parallel),
			zap.Bool("push", push),
			zap.String("registry", registry),
			zap.Bool("dry_run", dryRun),
			zap.String("filter", filter),
			zap.Strings("exclude", exclude))

		// Create build orchestrator
		orchestrator, err := build.NewBuildOrchestrator(rc, &build.OrchestratorConfig{
			Tag:             tag,
			Registry:        registry,
			Push:            push,
			Parallel:        parallel,
			Force:           force,
			Filter:          filter,
			Exclude:         exclude,
			ContinueOnError: continueOnError,
			DryRun:          dryRun,
		})
		if err != nil {
			logger.Error("Failed to create build orchestrator", zap.Error(err))
			return fmt.Errorf("failed to create build orchestrator: %w", err)
		}

		// Discover components
		components, err := orchestrator.DiscoverComponents(rc)
		if err != nil {
			logger.Error("Failed to discover components", zap.Error(err))
			return fmt.Errorf("failed to discover components: %w", err)
		}

		logger.Info("Discovered components for build",
			zap.Int("component_count", len(components)),
			zap.Strings("components", getComponentNames(components)))

		// Show build plan
		fmt.Printf("Build Plan:\n")
		fmt.Printf("═══════════\n")
		fmt.Printf("Components:     %d\n", len(components))
		fmt.Printf("Parallel:       %t\n", parallel)
		fmt.Printf("Tag:            %s\n", tag)
		if registry != "" {
			fmt.Printf("Registry:       %s\n", registry)
			fmt.Printf("Push:           %t\n", push)
		}
		fmt.Printf("Force Rebuild:  %t\n", force)
		fmt.Printf("\n")

		// Display component build order
		fmt.Printf("Build Order:\n")
		fmt.Printf("────────────\n")
		for i, component := range components {
			status := "pending"
			if dryRun {
				status = "would build"
			}
			fmt.Printf("  %d. %s (%s)\n", i+1, component.Name, status)
		}
		fmt.Printf("\n")

		// Dry run - show what would be built
		if dryRun {
			fmt.Printf(" Dry Run - No builds will be executed\n")
			return nil
		}

		// Execute builds
		startTime := time.Now()
		results, err := orchestrator.BuildAll(rc, components)
		if err != nil {
			logger.Error("Build orchestration failed", zap.Error(err))
			return fmt.Errorf("build orchestration failed: %w", err)
		}

		// Display results summary
		duration := time.Since(startTime)
		successful := 0
		failed := 0

		for _, result := range results {
			if result.Success {
				successful++
			} else {
				failed++
			}
		}

		fmt.Printf("Build Summary:\n")
		fmt.Printf("══════════════\n")
		fmt.Printf("Total:          %d components\n", len(results))
		fmt.Printf("Successful:     %d\n", successful)
		fmt.Printf("Failed:         %d\n", failed)
		fmt.Printf("Duration:       %s\n", duration)
		fmt.Printf("Parallel:       %t\n", parallel)
		fmt.Printf("\n")

		// Show individual results
		if len(results) > 0 {
			fmt.Printf("Component Results:\n")
			fmt.Printf("──────────────────\n")

			// Sort results by name for consistent output
			sort.Slice(results, func(i, j int) bool {
				return results[i].Component < results[j].Component
			})

			for _, result := range results {
				status := ""
				if !result.Success {
					status = "❌"
				}
				fmt.Printf("%s %-20s %s (%s)\n",
					status,
					result.Component,
					result.Tag,
					result.Duration)
			}
		}

		// Show failures if any
		if failed > 0 {
			fmt.Printf("\nFailed Builds:\n")
			fmt.Printf("──────────────\n")
			for _, result := range results {
				if !result.Success {
					fmt.Printf("❌ %s: %s\n", result.Component, result.Error)
				}
			}
		}

		logger.Info("Build all completed",
			zap.Int("total", len(results)),
			zap.Int("successful", successful),
			zap.Int("failed", failed),
			zap.Duration("duration", duration))

		if failed > 0 {
			return fmt.Errorf("%d component(s) failed to build", failed)
		}

		return nil
	}),
}

func init() {
	BuildCmd.AddCommand(allCmd)

	// Build configuration flags
	allCmd.Flags().String("tag", "", "Image tag for all components (defaults to git commit hash)")
	allCmd.Flags().String("registry", "", "Container registry URL")

	// Build behavior flags
	allCmd.Flags().Bool("parallel", false, "Enable parallel builds where dependencies allow")
	allCmd.Flags().Bool("push", false, "Push images to registry after build")
	allCmd.Flags().Bool("force-rebuild", false, "Force rebuild even if images exist")
	allCmd.Flags().Bool("continue-on-error", false, "Continue building other components if one fails")
	allCmd.Flags().Bool("dry-run", false, "Show build plan without executing")

	// Filtering flags
	allCmd.Flags().String("filter", "", "Filter components by name pattern (regex)")
	allCmd.Flags().StringSlice("exclude", nil, "Exclude specific components from build")

	// Progress and reporting flags
	allCmd.Flags().Bool("show-progress", true, "Show build progress")
	allCmd.Flags().String("output", "table", "Output format: table, json, yaml")

	allCmd.Example = `  # Build all components
  eos build all

  # Build all in parallel with push
  eos build all --parallel --push --registry registry.cybermonkey.net.au

  # Build with specific tag
  eos build all --tag v2.1.0

  # Build excluding specific components
  eos build all --exclude frontend,docs

  # Dry run to see build plan
  eos build all --parallel --dry-run`
}

// getComponentNames extracts component names from build components
func getComponentNames(components []*build.Component) []string {
	names := make([]string, len(components))
	for i, component := range components {
		names[i] = component.Name
	}
	return names
}
