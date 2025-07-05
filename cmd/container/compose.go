package container

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/container_management"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewComposeCmd creates the compose management command
func NewComposeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "compose",
		Aliases: []string{"comp"},
		Short:   "Manage Docker Compose projects",
		Long: `Manage Docker Compose projects including finding, starting, and stopping services.

This command provides comprehensive compose project management:
- Find all compose projects in specified directories
- Stop all running compose projects
- Individual project operations

Examples:
  eos container compose find               # Find all compose projects
  eos container compose stop               # Stop all compose projects
  eos container compose list               # List compose projects with status`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			otelzap.Ctx(rc.Ctx).Info("No subcommand provided for compose command")
			_ = cmd.Help()
			return nil
		}),
	}

	// Add subcommands
	cmd.AddCommand(newComposeFindCmd())
	cmd.AddCommand(newComposeStopCmd())
	cmd.AddCommand(newComposeListCmd())

	return cmd
}

// newComposeFindCmd creates the compose find subcommand
func newComposeFindCmd() *cobra.Command {
	var searchPaths []string

	cmd := &cobra.Command{
		Use:     "find",
		Aliases: []string{"search", "discover"},
		Short:   "Find Docker Compose projects",
		Long: `Find all Docker Compose projects in specified directories.

Searches recursively through directories looking for docker-compose.yml, 
docker-compose.yaml, compose.yml, or compose.yaml files.

Examples:
  eos container compose find                          # Search default paths
  eos container compose find --path /opt --path /srv # Search specific paths
  eos container compose find --json                  # Output in JSON format`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			
			outputJSON, _ := cmd.Flags().GetBool("json")

			logger.Info("Finding Docker Compose projects", 
				zap.Strings("search_paths", searchPaths),
				zap.Bool("json", outputJSON))

			manager := container_management.NewContainerManager(nil)
			result, err := manager.FindComposeProjects(rc, searchPaths)
			if err != nil {
				logger.Error("Failed to find compose projects", zap.Error(err))
				return err
			}

			if outputJSON {
				return outputComposeSearchJSON(result)
			}

			return outputComposeSearchTable(result)
		}),
	}

	cmd.Flags().StringSliceVarP(&searchPaths, "path", "p", []string{}, "Search paths (default: $HOME, /opt, /srv, /home)")
	cmd.Flags().Bool("json", false, "Output in JSON format")

	return cmd
}

// newComposeStopCmd creates the compose stop subcommand
func newComposeStopCmd() *cobra.Command {
	var (
		searchPaths     []string
		force           bool
		dryRun          bool
		noConfirm       bool
		removeVolumes   bool
		removeImages    bool
		timeout         int
		ignoreRunning   bool
	)

	cmd := &cobra.Command{
		Use:     "stop",
		Aliases: []string{"down", "shutdown"},
		Short:   "Stop all Docker Compose projects",
		Long: `Stop all Docker Compose projects found in search directories.

This command finds all compose projects and stops them using 'docker compose down'.
It can handle running containers and provides confirmation prompts for safety.

Examples:
  eos container compose stop                          # Stop all projects with confirmation
  eos container compose stop --force                 # Stop without confirmation
  eos container compose stop --dry-run               # Show what would be stopped
  eos container compose stop --remove-volumes        # Remove volumes when stopping
  eos container compose stop --path /opt             # Stop projects in specific path`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			
			outputJSON, _ := cmd.Flags().GetBool("json")

			options := &container_management.ComposeStopOptions{
				SearchPaths:    searchPaths,
				ConfirmEach:    !noConfirm,
				Force:          force,
				StopContainers: true,
				IgnoreRunning:  ignoreRunning,
				DryRun:         dryRun,
				RemoveVolumes:  removeVolumes,
				RemoveImages:   removeImages,
				Timeout:        timeout,
			}

			logger.Info("Stopping Docker Compose projects", 
				zap.Strings("search_paths", searchPaths),
				zap.Bool("force", force),
				zap.Bool("dry_run", dryRun))

			manager := container_management.NewContainerManager(nil)
			result, err := manager.StopAllComposeProjects(rc, options)
			if err != nil {
				logger.Error("Failed to stop compose projects", zap.Error(err))
				return err
			}

			if outputJSON {
				return outputComposeStopJSON(result)
			}

			return outputComposeStopTable(result)
		}),
	}

	cmd.Flags().StringSliceVarP(&searchPaths, "path", "p", []string{}, "Search paths (default: $HOME, /opt, /srv, /home)")
	cmd.Flags().BoolVar(&force, "force", false, "Force stop without confirmation")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without making changes")
	cmd.Flags().BoolVar(&noConfirm, "no-confirm", false, "Don't confirm each project (same as --force)")
	cmd.Flags().BoolVar(&removeVolumes, "remove-volumes", false, "Remove named volumes declared in the volumes section")
	cmd.Flags().BoolVar(&removeImages, "remove-images", false, "Remove all images used by services")
	cmd.Flags().IntVar(&timeout, "timeout", 30, "Timeout in seconds for stopping containers")
	cmd.Flags().BoolVar(&ignoreRunning, "ignore-running", false, "Don't check for running containers first")
	cmd.Flags().Bool("json", false, "Output in JSON format")

	return cmd
}

// newComposeListCmd creates the compose list subcommand
func newComposeListCmd() *cobra.Command {
	var searchPaths []string

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List Docker Compose projects with status",
		Long: `List all Docker Compose projects with their current status.

Shows project path, compose file, and running status for each found project.

Examples:
  eos container compose list                          # List all projects
  eos container compose list --path /opt             # List projects in specific path
  eos container compose list --json                  # Output in JSON format`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			
			outputJSON, _ := cmd.Flags().GetBool("json")

			logger.Info("Listing Docker Compose projects", 
				zap.Strings("search_paths", searchPaths))

			manager := container_management.NewContainerManager(nil)
			result, err := manager.FindComposeProjects(rc, searchPaths)
			if err != nil {
				logger.Error("Failed to list compose projects", zap.Error(err))
				return err
			}

			if outputJSON {
				return outputComposeSearchJSON(result)
			}

			return outputComposeListTable(result)
		}),
	}

	cmd.Flags().StringSliceVarP(&searchPaths, "path", "p", []string{}, "Search paths (default: $HOME, /opt, /srv, /home)")
	cmd.Flags().Bool("json", false, "Output in JSON format")

	return cmd
}

// Output formatting functions

func outputComposeSearchJSON(result *container_management.ComposeSearchResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputComposeSearchTable(result *container_management.ComposeSearchResult) error {
	fmt.Printf("Searched paths: %s\n", strings.Join(result.SearchPaths, ", "))
	fmt.Printf("Search duration: %v\n", result.SearchDuration)
	fmt.Printf("Projects found: %d\n\n", result.TotalFound)

	if result.TotalFound == 0 {
		fmt.Println("No compose projects found.")
		return nil
	}

	for _, project := range result.Projects {
		fmt.Printf("Path: %s\n", project.Path)
		fmt.Printf("  Compose file: %s\n", project.ComposeFile)
		if project.Status != "" {
			fmt.Printf("  Status: %s\n", project.Status)
		}
		fmt.Printf("  Last seen: %s\n", project.LastSeen.Format("2006-01-02 15:04:05"))
		fmt.Println()
	}

	return nil
}

func outputComposeListTable(result *container_management.ComposeSearchResult) error {
	if result.TotalFound == 0 {
		fmt.Println("No compose projects found.")
		return nil
	}

	fmt.Printf("Found %d compose projects\n\n", result.TotalFound)

	// Print header
	fmt.Printf("%-40s %-20s %-10s %s\n", "PATH", "COMPOSE FILE", "STATUS", "LAST SEEN")
	fmt.Println(strings.Repeat("-", 90))

	// Print projects
	for _, project := range result.Projects {
		status := project.Status
		if status == "" {
			status = "unknown"
		}

		fmt.Printf("%-40s %-20s %-10s %s\n",
			truncateString(project.Path, 40),
			project.ComposeFile,
			status,
			project.LastSeen.Format("01-02 15:04"))
	}

	return nil
}

func outputComposeStopJSON(result *container_management.ComposeMultiStopResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputComposeStopTable(result *container_management.ComposeMultiStopResult) error {
	summary := result.Summary

	fmt.Printf("Compose Stop Summary:\n")
	fmt.Printf("  Total projects: %d\n", summary.TotalProjects)
	fmt.Printf("  Successfully stopped: %d\n", summary.ProjectsStopped)
	fmt.Printf("  Skipped: %d\n", summary.ProjectsSkipped)
	fmt.Printf("  Failed: %d\n", summary.ProjectsFailed)
	fmt.Printf("  Duration: %v\n", summary.Duration)
	fmt.Printf("  Success: %t\n\n", summary.Success)

	if len(result.Operations) > 0 {
		fmt.Println("Operations:")
		for _, op := range result.Operations {
			status := "✓"
			if !op.Success {
				status = "✗"
			}
			if op.DryRun {
				status = "[DRY RUN]"
			}

			fmt.Printf("  %s %s: %s\n", status, op.Project.Path, op.Message)
		}
	}

	if len(summary.Errors) > 0 {
		fmt.Println("\nErrors:")
		for _, err := range summary.Errors {
			fmt.Printf("  ✗ %s\n", err)
		}
	}

	return nil
}