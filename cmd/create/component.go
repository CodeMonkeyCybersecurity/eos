package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/build"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var componentCmd = &cobra.Command{
	Use:   "component [component-name]",
	Short: "Build a specific component",
	Long: `Build a specific component with advanced build options and dependency management.

This command builds individual components following the assessment→intervention→evaluation
pattern to ensure reliable and reproducible builds. It supports various build strategies,
artifact management, and integration with the  → Terraform → Nomad orchestration.

The build process includes:
- Dependency resolution and validation
- Source code compilation and packaging
- Docker image creation and optimization
- Artifact validation and testing
- Build metadata and tagging
- Integration with deployment pipeline

Examples:
  # Build helen component
  eos build component helen

  # Build with specific tag
  eos build component helen --tag v2.1.0

  # Build with custom build args
  eos build component helen --build-arg VERSION=2.1.0 --build-arg ENV=production

  # Build and push to registry
  eos build component helen --push --registry registry.cybermonkey.net.au

  # Build with dependency check
  eos build component helen --with-dependencies --force-rebuild`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		componentName := args[0]

		logger.Info("Building component",
			zap.String("command", "build component"),
			zap.String("component", componentName),
			zap.String("context", rc.Component))

		// Parse flags
		tag, _ := cmd.Flags().GetString("tag")
		push, _ := cmd.Flags().GetBool("push")
		registry, _ := cmd.Flags().GetString("registry")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force-rebuild")
		withDeps, _ := cmd.Flags().GetBool("with-dependencies")
		buildArgs, _ := cmd.Flags().GetStringSlice("build-arg")
		target, _ := cmd.Flags().GetString("target")
		parallel, _ := cmd.Flags().GetBool("parallel")

		logger.Debug("Build configuration",
			zap.String("component", componentName),
			zap.String("tag", tag),
			zap.Bool("push", push),
			zap.String("registry", registry),
			zap.Bool("dry_run", dryRun),
			zap.Bool("force_rebuild", force),
			zap.Bool("with_dependencies", withDeps),
			zap.Strings("build_args", buildArgs))

		// Create build configuration
		buildConfig := &build.ComponentBuildConfig{
			Name:             componentName,
			Tag:              tag,
			Registry:         registry,
			Push:             push,
			Force:            force,
			WithDependencies: withDeps,
			BuildArgs:        buildArgsToMap(buildArgs),
			Target:           target,
			Parallel:         parallel,
			DryRun:           dryRun,
		}

		// Create component builder
		builder, err := build.NewComponentBuilder(rc, buildConfig)
		if err != nil {
			logger.Error("Failed to create component builder", zap.Error(err))
			return fmt.Errorf("failed to create component builder: %w", err)
		}

		// Execute build
		result, err := builder.Build(rc)
		if err != nil {
			logger.Error("Component build failed",
				zap.String("component", componentName),
				zap.Error(err))
			return fmt.Errorf("component build failed: %w", err)
		}

		// Display build results
		fmt.Printf(" Component '%s' built successfully\n", componentName)
		fmt.Printf("\nBuild Results:\n")
		fmt.Printf("──────────────\n")
		fmt.Printf("Component:    %s\n", result.Component)
		fmt.Printf("Tag:          %s\n", result.Tag)
		fmt.Printf("Image:        %s\n", result.ImageName)
		fmt.Printf("Duration:     %s\n", result.Duration)
		fmt.Printf("Size:         %s\n", result.ImageSize)

		if len(result.Artifacts) > 0 {
			fmt.Printf("\nArtifacts:\n")
			for _, artifact := range result.Artifacts {
				fmt.Printf("  • %s (%s)\n", artifact.Name, artifact.Type)
			}
		}

		if result.Registry != "" {
			fmt.Printf("\nRegistry:     %s\n", result.Registry)
			fmt.Printf("Pushed:       %t\n", result.Pushed)
		}

		logger.Info("Component build completed successfully",
			zap.String("component", componentName),
			zap.String("tag", result.Tag),
			zap.Duration("duration", result.Duration))

		return nil
	}),
}

func init() {
	buildCmd.AddCommand(componentCmd)

	// Build configuration flags
	componentCmd.Flags().String("tag", "", "Image tag (defaults to git commit hash)")
	componentCmd.Flags().String("registry", "", "Container registry URL")
	componentCmd.Flags().String("target", "", "Dockerfile target stage")
	componentCmd.Flags().StringSlice("build-arg", nil, "Build arguments (key=value)")

	// Build behavior flags
	componentCmd.Flags().Bool("push", false, "Push image to registry after build")
	componentCmd.Flags().Bool("force-rebuild", false, "Force rebuild even if image exists")
	componentCmd.Flags().Bool("with-dependencies", false, "Build dependencies first")
	componentCmd.Flags().Bool("parallel", false, "Enable parallel builds for dependencies")
	componentCmd.Flags().Bool("dry-run", false, "Show what would be built without executing")

	// Cache and optimization flags
	componentCmd.Flags().Bool("no-cache", false, "Disable build cache")
	componentCmd.Flags().String("cache-from", "", "External cache source")
	componentCmd.Flags().String("cache-to", "", "External cache destination")

	componentCmd.Example = `  # Build helen component
  eos build component helen

  # Build with specific tag and push
  eos build component helen --tag v2.1.0 --push

  # Build with custom build arguments
  eos build component helen --build-arg VERSION=2.1.0 --build-arg ENV=prod

  # Build with dependencies
  eos build component helen --with-dependencies --parallel

  # Dry run build
  eos build component helen --tag latest --dry-run`
}

// buildArgsToMap converts build-arg slice to map
func buildArgsToMap(buildArgs []string) map[string]string {
	result := make(map[string]string)
	for _, arg := range buildArgs {
		if idx := len(arg); idx > 0 {
			// Find = separator
			for i := 0; i < len(arg); i++ {
				if arg[i] == '=' {
					key := arg[:i]
					value := arg[i+1:]
					result[key] = value
					break
				}
			}
		}
	}
	return result
}
