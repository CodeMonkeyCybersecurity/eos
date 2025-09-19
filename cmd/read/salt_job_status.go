// cmd/read/salt_job_status.go
package read

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var nomadJobStatusCmd = &cobra.Command{
	Use:     "nomad-job-status <job-id>",
	Aliases: []string{"job-status", "nomad-job-info"},
	Short:   "Get detailed Nomad job status and information",
	Long: `Get detailed status and information for a specific Nomad job.

This command retrieves comprehensive information about a Nomad job including:
- Current execution status and progress
- Job specification and configuration
- Allocation status across nodes
- Start time, duration, and completion time
- Error messages and failure details

Examples:
  eos read nomad-job-status my-web-service      # Get job status
  eos read nomad-job-status my-web-service --json  # Output in JSON format
  eos read nomad-job-status my-web-service --details  # Include full allocation details

Job States:
  - pending: Job is queued for scheduling
  - running: Job is currently executing
  - complete: Job finished successfully  
  - failed: Job completed with errors
  - dead: Job was stopped or killed`,

	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		jobID := args[0]

		// Parse flags
		_, _ = cmd.Flags().GetBool("json")
		includeDetails, _ := cmd.Flags().GetBool("details")

		logger.Info("Getting Nomad job status",
			zap.String("job_id", jobID),
			zap.Bool("include_details", includeDetails))

		// TODO: Implement Nomad job status retrieval
		// This should use the Nomad API to get job status
		logger.Info("terminal prompt: Nomad job status retrieval not yet implemented")
		logger.Info("terminal prompt: Job ID:", zap.String("job_id", jobID))
		logger.Info("terminal prompt: Use 'nomad job status" + jobID + "' directly for now")
		return fmt.Errorf("Nomad job status integration pending - use nomad CLI directly")
	}),
}

func init() {
	nomadJobStatusCmd.Flags().Bool("json", false, "Output results in JSON format")
	nomadJobStatusCmd.Flags().Bool("details", false, "Include full allocation details")

	ReadCmd.AddCommand(nomadJobStatusCmd)
}

