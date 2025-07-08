// cmd/list/salt_jobs.go
package list

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt/client"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var saltJobsCmd = &cobra.Command{
	Use:     "salt-jobs",
	Aliases: []string{"salt-job-list", "saltstack-jobs"},
	Short:   "List recent Salt jobs",
	Long: `List recent Salt jobs with filtering and search capabilities.

Salt jobs represent the execution of commands, states, or orchestrations on minions.
This command shows recent job history with details about execution status, functions,
and minion targets.

Examples:
  eos list salt-jobs                           # List recent jobs
  eos list salt-jobs --limit 50               # List last 50 jobs  
  eos list salt-jobs --function state.apply   # Filter by function
  eos list salt-jobs --json                   # Output in JSON format

Job States:
  - Running: Job is currently executing
  - Complete: Job finished successfully
  - Failed: Job completed with errors
  - Killed: Job was manually terminated
  - Timeout: Job exceeded time limit`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Parse flags
		limit, _ := cmd.Flags().GetInt("limit")
		functionFilter, _ := cmd.Flags().GetString("function")
		outputJSON, _ := cmd.Flags().GetBool("json")
		includeComplete, _ := cmd.Flags().GetBool("include-complete")

		logger.Info("Listing Salt jobs",
			zap.Int("limit", limit),
			zap.String("function_filter", functionFilter),
			zap.Bool("include_complete", includeComplete))

		// Create Salt client
		saltClient := client.NewSaltClient()

		// Create context with timeout
		ctx, cancel := context.WithTimeout(rc.Ctx, 30*time.Second)
		defer cancel()

		// Get job list
		jobs, err := saltClient.ListJobs(ctx, limit, functionFilter, includeComplete)
		if err != nil {
			logger.Error("Failed to list Salt jobs", zap.Error(err))
			return fmt.Errorf("failed to list Salt jobs: %w", err)
		}

		// Output results
		if outputJSON {
			return outputJobsJSON(jobs)
		}

		return outputJobsTable(jobs, logger)
	}),
}

func init() {
	saltJobsCmd.Flags().Int("limit", 20, "Maximum number of jobs to list")
	saltJobsCmd.Flags().String("function", "", "Filter jobs by function name")
	saltJobsCmd.Flags().Bool("include-complete", true, "Include completed jobs in results")
	saltJobsCmd.Flags().Bool("json", false, "Output results in JSON format")

	ListCmd.AddCommand(saltJobsCmd)
}

func outputJobsJSON(jobs interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(jobs)
}

func outputJobsTable(jobs interface{}, logger *zap.Logger) error {
	fmt.Println("Recent Salt Jobs")
	fmt.Println(strings.Repeat("=", 80))

	// This would need to be implemented based on the actual job data structure
	// from the Salt client. For now, showing the pattern:

	fmt.Printf("%-20s %-15s %-20s %-15s %s\n",
		"JOB ID", "STATE", "FUNCTION", "START TIME", "TARGET")
	fmt.Println(strings.Repeat("-", 80))

	// TODO: Implement actual job listing based on Salt client response format
	fmt.Println("(Job listing implementation pending Salt client structure)")

	return nil
}
