package build

import (
	"github.com/spf13/cobra"
)

// BuildCmd represents the build command
var BuildCmd = &cobra.Command{
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

Available Commands:
  build      Build specific component or all components
  validate   Validate build configuration and dependencies
  clean      Clean build artifacts and caches

Examples:
  # Build all components
  eos build --all

  # Build specific component
  eos build helen

  # Build with custom tag
  eos build helen --tag v2.1.0

  # Parallel build with dependencies
  eos build --all --parallel --with-dependencies

  # Validate build configuration
  eos validate helen --strict`,
	Aliases: []string{"compile", "make"},
}

func init() {
	// This function will be called by the root command to register this command
}
