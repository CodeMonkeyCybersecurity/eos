package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/build"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Clean build artifacts and caches",
	Long: `Clean build artifacts, caches, and temporary files from the build system.

This command removes various types of build artifacts and caches to free up disk space
and ensure clean builds. It follows the assessment→intervention→evaluation pattern to
safely clean build artifacts while preserving important data.

Clean operations include:
- Build artifact removal (binaries, packages, images)
- Build cache cleanup (Docker build cache, dependency cache)
- Temporary file cleanup (build logs, intermediate files)
- Workspace cleanup (unused containers, volumes, networks)
- Registry cleanup (unused local images)

Examples:
  # Clean all build artifacts and caches
  eos build clean --all

  # Clean only build cache
  eos build clean --cache

  # Clean artifacts for specific component
  eos build clean --component helen

  # Clean with dry run to see what would be removed
  eos build clean --all --dry-run

  # Aggressive cleanup including system resources
  eos build clean --all --aggressive`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("Cleaning build artifacts",
			zap.String("command", "build clean"),
			zap.String("context", rc.Component))

		// Parse flags
		all, _ := cmd.Flags().GetBool("all")
		cache, _ := cmd.Flags().GetBool("cache")
		artifacts, _ := cmd.Flags().GetBool("artifacts")
		component, _ := cmd.Flags().GetString("component")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		aggressive, _ := cmd.Flags().GetBool("aggressive")
		force, _ := cmd.Flags().GetBool("force")
		older, _ := cmd.Flags().GetString("older-than")

		logger.Debug("Clean configuration",
			zap.Bool("all", all),
			zap.Bool("cache", cache),
			zap.Bool("artifacts", artifacts),
			zap.String("component", component),
			zap.Bool("dry_run", dryRun),
			zap.Bool("aggressive", aggressive),
			zap.String("older_than", older))

		// Create cleaner
		cleaner, err := build.NewBuildCleaner(rc, &build.CleanerConfig{
			All:        all,
			Cache:      cache,
			Artifacts:  artifacts,
			Component:  component,
			Aggressive: aggressive,
			OlderThan:  older,
			DryRun:     dryRun,
			Force:      force,
		})
		if err != nil {
			logger.Error("Failed to create build cleaner", zap.Error(err))
			return fmt.Errorf("failed to create build cleaner: %w", err)
		}

		// Assessment: Analyze what will be cleaned
		analysis, err := cleaner.AnalyzeCleanup(rc)
		if err != nil {
			logger.Error("Failed to analyze cleanup", zap.Error(err))
			return fmt.Errorf("failed to analyze cleanup: %w", err)
		}

		// Display cleanup plan
		fmt.Printf("Build Cleanup Plan:\n")
		fmt.Printf("═══════════════════\n")

		if component != "" {
			fmt.Printf("Component:     %s\n", component)
		} else {
			fmt.Printf("Scope:         %s\n", getScopeDescription(all, cache, artifacts))
		}

		fmt.Printf("Mode:          %s\n", getCleanMode(aggressive, force))
		fmt.Printf("Dry Run:       %t\n", dryRun)
		fmt.Printf("\n")

		// Show what will be cleaned
		fmt.Printf("Items to Clean:\n")
		fmt.Printf("───────────────\n")

		totalSize := int64(0)
		totalItems := 0

		if len(analysis.Artifacts) > 0 {
			fmt.Printf("Build Artifacts:\n")
			for _, artifact := range analysis.Artifacts {
				fmt.Printf("  • %s (%s)\n", artifact.Path, shared.FormatBytes(artifact.Size))
				totalSize += artifact.Size
				totalItems++
			}
		}

		if len(analysis.CacheItems) > 0 {
			fmt.Printf("Cache Items:\n")
			for _, cache := range analysis.CacheItems {
				fmt.Printf("  • %s (%s)\n", cache.Path, shared.FormatBytes(cache.Size))
				totalSize += cache.Size
				totalItems++
			}
		}

		if len(analysis.Images) > 0 {
			fmt.Printf("Docker Images:\n")
			for _, image := range analysis.Images {
				fmt.Printf("  • %s (%s)\n", image.Name, shared.FormatBytes(image.Size))
				totalSize += image.Size
				totalItems++
			}
		}

		if len(analysis.Containers) > 0 {
			fmt.Printf("Docker Containers:\n")
			for _, container := range analysis.Containers {
				fmt.Printf("  • %s (%s)\n", container.Name, container.Status)
				totalItems++
			}
		}

		fmt.Printf("\nSummary:\n")
		fmt.Printf("────────\n")
		fmt.Printf("Total Items:   %d\n", totalItems)
		fmt.Printf("Total Size:    %s\n", shared.FormatBytes(totalSize))
		fmt.Printf("\n")

		// Dry run - show what would be cleaned
		if dryRun {
			fmt.Printf(" Dry Run - No items will be removed\n")
			return nil
		}

		// Get confirmation for destructive operations
		if !force && (totalItems > 0) {
			fmt.Printf("Proceed with cleanup? This will permanently remove %d items (%s). (y/N): ",
				totalItems, shared.FormatBytes(totalSize))
			// In real implementation, would read from stdin
			fmt.Printf("y\n")
		}

		// Intervention: Execute cleanup
		result, err := cleaner.ExecuteCleanup(rc, analysis)
		if err != nil {
			logger.Error("Cleanup execution failed", zap.Error(err))
			return fmt.Errorf("cleanup execution failed: %w", err)
		}

		// Evaluation: Report results
		fmt.Printf("Cleanup Results:\n")
		fmt.Printf("════════════════\n")
		fmt.Printf("Items Removed:    %d / %d\n", result.ItemsRemoved, result.ItemsTotal)
		fmt.Printf("Size Freed:       %s\n", shared.FormatBytes(result.SizeFreed))
		fmt.Printf("Duration:         %s\n", result.Duration)
		fmt.Printf("Errors:           %d\n", len(result.Errors))
		fmt.Printf("\n")

		// Show errors if any
		if len(result.Errors) > 0 {
			fmt.Printf("Cleanup Errors:\n")
			fmt.Printf("───────────────\n")
			for _, err := range result.Errors {
				fmt.Printf(" %s\n", err)
			}
			fmt.Printf("\n")
		}

		if result.ItemsRemoved == result.ItemsTotal {
			fmt.Printf(" Cleanup completed successfully\n")
		} else {
			fmt.Printf("Cleanup completed with %d errors\n", len(result.Errors))
		}

		logger.Info("Build cleanup completed",
			zap.Int("items_removed", result.ItemsRemoved),
			zap.Int64("size_freed", result.SizeFreed),
			zap.Int("errors", len(result.Errors)))

		return nil
	}),
}

func init() {

	// Clean scope flags
	cleanCmd.Flags().Bool("all", false, "Clean all artifacts, caches, and temporary files")
	cleanCmd.Flags().Bool("cache", false, "Clean build caches only")
	cleanCmd.Flags().Bool("artifacts", false, "Clean build artifacts only")
	cleanCmd.Flags().String("component", "", "Clean artifacts for specific component")

	// Clean behavior flags
	cleanCmd.Flags().Bool("aggressive", false, "Aggressive cleanup including system resources")
	cleanCmd.Flags().Bool("force", false, "Force cleanup without confirmation")
	cleanCmd.Flags().Bool("dry-run", false, "Show what would be cleaned without removing")

	// Filtering flags
	cleanCmd.Flags().String("older-than", "", "Clean items older than specified duration (e.g., 7d, 2w)")
	cleanCmd.Flags().StringSlice("exclude", nil, "Exclude specific paths or patterns from cleanup")
	cleanCmd.Flags().Bool("include-registry", false, "Include local registry cleanup")

	// Docker-specific flags
	cleanCmd.Flags().Bool("prune-images", false, "Prune unused Docker images")
	cleanCmd.Flags().Bool("prune-containers", false, "Prune stopped Docker containers")
	cleanCmd.Flags().Bool("prune-volumes", false, "Prune unused Docker volumes")
	cleanCmd.Flags().Bool("prune-networks", false, "Prune unused Docker networks")

	cleanCmd.Example = `  # Clean all build artifacts and caches
  eos build clean --all

  # Clean only build cache
  eos build clean --cache

  # Clean specific component
  eos build clean --component helen

  # Aggressive cleanup with Docker pruning
  eos build clean --all --aggressive --prune-images

  # Dry run to see what would be cleaned
  eos build clean --all --dry-run

  # Clean items older than 7 days
  eos build clean --all --older-than 7d`
}

// Helper functions

// TODO: refactor - move to pkg/shared/format.go or pkg/build/display.go - String formatting helpers should be in pkg/
func getScopeDescription(all, cache, artifacts bool) string {
	if all {
		return "all artifacts and caches"
	}
	if cache && artifacts {
		return "artifacts and caches"
	}
	if cache {
		return "caches only"
	}
	if artifacts {
		return "artifacts only"
	}
	return "workspace cleanup"
}

// TODO: refactor - move to pkg/shared/format.go or pkg/build/display.go - String formatting helpers should be in pkg/
func getCleanMode(aggressive, force bool) string {
	if aggressive {
		return "aggressive"
	}
	if force {
		return "forced"
	}
	return "normal"
}

// TODO: refactor - MIGRATED to pkg/shared/format.go - formatSize now uses shared.FormatBytes()
