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

var saltJobStatusCmd = &cobra.Command{
	Use:     "salt-job-status <job-id>",
	Aliases: []string{"salt-job-info", "saltstack-job-status"},
	Short:   "Get detailed Salt job status and information",
	Long: `Get detailed status and information for a specific Salt job.

This command retrieves comprehensive information about a Salt job including:
- Current execution status and progress
- Function being executed and arguments
- Target minions and their individual status
- Start time, duration, and completion time
- Error messages and failure details

Examples:
  eos read salt-job-status 20240112123456789      # Get job status
  eos read salt-job-status 20240112123456789 --json  # Output in JSON format
  eos read salt-job-status 20240112123456789 --details  # Include full response details

Job States:
  - Running: Job is currently executing
  - Complete: Job finished successfully  
  - Failed: Job completed with errors
  - Killed: Job was manually terminated
  - Timeout: Job exceeded time limit`,

	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		jobID := args[0]

		// Parse flags
		_, _ = cmd.Flags().GetBool("json")
		includeDetails, _ := cmd.Flags().GetBool("details")

		logger.Info("Getting Salt job status",
			zap.String("job_id", jobID),
			zap.Bool("include_details", includeDetails))

		// Temporarily disabled due to interface changes
		logger.Warn("Salt job status feature temporarily disabled during refactoring",
			zap.String("job_id", jobID))
		return fmt.Errorf("GetJobStatus method not available in current saltstack.KeyManager interface")
	}),
}

func init() {
	saltJobStatusCmd.Flags().Bool("json", false, "Output results in JSON format")
	saltJobStatusCmd.Flags().Bool("details", false, "Include full response details from minions")

	ReadCmd.AddCommand(saltJobStatusCmd)
}

