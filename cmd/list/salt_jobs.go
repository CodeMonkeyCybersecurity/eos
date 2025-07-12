// cmd/list/salt_jobs.go
package list

import (
	"context"
	"fmt"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	out "github.com/CodeMonkeyCybersecurity/eos/pkg/output"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
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
		saltClient := saltstack.NewClient(otelzap.Ctx(rc.Ctx))

		// Create context with timeout
		ctx, cancel := context.WithTimeout(rc.Ctx, 30*time.Second)
		defer cancel()

		// Get job list using basic Salt command
		cmdOutput, err := saltClient.CmdRun(ctx, "*", "saltutil.running")
		if err != nil {
			logger.Error("Failed to list Salt jobs", zap.Error(err))
			return fmt.Errorf("failed to list Salt jobs: %w", err)
		}

		// For now, just return the raw output as jobs
		jobs := map[string]interface{}{"output": cmdOutput}

		// Output results
		if outputJSON {
			return out.JSONToStdout(jobs)
		}

		// Create table output
		tw := out.NewTable().
			WithHeaders("JOB ID", "STATE", "FUNCTION", "START TIME", "TARGET")

		// TODO: Add actual job data once Salt client response format is known
		logger.Info("Recent Salt Jobs")
		tw.AddRow("(Job listing implementation pending Salt client structure)", "", "", "", "")

		return tw.Render()
	}),
}

func init() {
	saltJobsCmd.Flags().Int("limit", 20, "Maximum number of jobs to list")
	saltJobsCmd.Flags().String("function", "", "Filter jobs by function name")
	saltJobsCmd.Flags().Bool("include-complete", true, "Include completed jobs in results")
	saltJobsCmd.Flags().Bool("json", false, "Output results in JSON format")

	ListCmd.AddCommand(saltJobsCmd)
}

// All output formatting functions have been moved to pkg/output/
