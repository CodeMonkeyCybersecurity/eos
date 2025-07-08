// cmd/salt/job.go
package salt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt/client"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	jobListLimit    int
	jobListFunction string
	jobWatchTimeout int
)

// SaltJobCmd manages Salt jobs (list, status, kill, results)
var SaltJobCmd = &cobra.Command{
	Use:   "job [command] [job-id]",
	Short: "Manage Salt jobs - list, monitor, and control job execution",
	Long: `Manage Salt jobs including listing, monitoring status, viewing results, and killing jobs.

Salt jobs represent the execution of commands, states, or orchestrations on minions.
This command provides comprehensive job management capabilities for monitoring
and controlling Salt operations.

Commands:
  list             - List recent jobs
  status [job-id]  - Get detailed job status
  result [job-id]  - Get job execution results
  kill [job-id]    - Kill a running job
  watch [job-id]   - Watch job progress in real-time

Examples:
  eos salt job list                           # List recent jobs
  eos salt job list --limit 50               # List last 50 jobs
  eos salt job list --function state.apply   # Filter by function
  eos salt job status 20240112123456789      # Get job status
  eos salt job result 20240112123456789      # Get job results
  eos salt job kill 20240112123456789        # Kill running job
  eos salt job watch 20240112123456789       # Watch job progress
  eos salt job watch 20240112123456789 --timeout 600  # Watch with 10min timeout
  
Job States:
  - Running: Job is currently executing
  - Complete: Job finished successfully
  - Failed: Job completed with errors
  - Killed: Job was manually terminated
  - Timeout: Job exceeded time limit
  
Real-time Monitoring:
  The watch command provides live updates on job progress, showing:
  - Current execution status
  - Minion responses as they arrive
  - Error messages and failures
  - Final results summary`,

	Args: cobra.MinimumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		subcommand := args[0]
		
		logger.Info("Starting Salt job management",
			zap.String("subcommand", subcommand))

		// Get Salt client configuration
		config, err := getSaltConfig()
		if err != nil {
			return fmt.Errorf("Salt configuration error: %w", err)
		}

		// Create Salt client
		clientConfig := &client.ClientConfig{
			BaseURL:       config.URL,
			Username:      config.Username,
			Password:      config.Password,
			Eauth:         config.Eauth,
			Timeout:       time.Duration(config.Timeout) * time.Second,
			MaxRetries:    config.Retries,
			RetryDelay:    2 * time.Second,
		}

		saltClient, err := client.NewHTTPSaltClient(rc, clientConfig)
		if err != nil {
			return fmt.Errorf("failed to create Salt client: %w", err)
		}

		// Authenticate with Salt API
		logger.Info("Authenticating with Salt API")
		_, err = saltClient.Login(rc.Ctx, nil)
		if err != nil {
			return fmt.Errorf("Salt API authentication failed: %w", err)
		}
		defer func() {
			if err := saltClient.Logout(rc.Ctx); err != nil {
				logger.Warn("Failed to logout from Salt API", zap.Error(err))
			}
		}()

		// Route to appropriate subcommand
		switch subcommand {
		case "list":
			return handleJobList(rc.Ctx, saltClient)
		case "status":
			if len(args) < 2 {
				return fmt.Errorf("job ID required for status command")
			}
			return handleJobStatus(rc.Ctx, saltClient, args[1])
		case "result":
			if len(args) < 2 {
				return fmt.Errorf("job ID required for result command")
			}
			return handleJobResult(rc.Ctx, saltClient, args[1])
		case "kill":
			if len(args) < 2 {
				return fmt.Errorf("job ID required for kill command")
			}
			return handleJobKill(rc.Ctx, saltClient, args[1])
		case "watch":
			if len(args) < 2 {
				return fmt.Errorf("job ID required for watch command")
			}
			return handleJobWatch(rc.Ctx, saltClient, args[1])
		default:
			return fmt.Errorf("unknown job subcommand: %s", subcommand)
		}
	}),
}

func init() {
	// Add job-specific flags
	SaltJobCmd.Flags().IntVar(&jobListLimit, "limit", 20, "Number of jobs to list")
	SaltJobCmd.Flags().StringVar(&jobListFunction, "function", "", "Filter jobs by function name")
	SaltJobCmd.Flags().IntVar(&jobWatchTimeout, "timeout", 300, "Watch timeout in seconds")
}

// handleJobList lists recent Salt jobs
func handleJobList(ctx context.Context, saltClient client.SaltClient) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Listing Salt jobs",
		zap.Int("limit", jobListLimit),
		zap.String("function_filter", jobListFunction))

	opts := &client.JobListOptions{
		Limit: jobListLimit,
	}
	
	if jobListFunction != "" {
		opts.SearchFunction = jobListFunction
	}

	jobs, err := saltClient.ListJobs(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to list jobs: %w", err)
	}

	if jsonOutput {
		return displayJobListJSON(jobs)
	}

	return displayJobListTable(ctx, jobs)
}

// handleJobStatus shows detailed status for a specific job
func handleJobStatus(ctx context.Context, saltClient client.SaltClient, jobID string) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Getting job status", zap.String("job_id", jobID))

	job, err := saltClient.GetJob(ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to get job status: %w", err)
	}

	if jsonOutput {
		return displayJobStatusJSON(job)
	}

	return displayJobStatusTable(ctx, job)
}

// handleJobResult shows execution results for a specific job
func handleJobResult(ctx context.Context, saltClient client.SaltClient, jobID string) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Getting job results", zap.String("job_id", jobID))

	job, err := saltClient.GetJob(ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to get job results: %w", err)
	}

	if jsonOutput {
		return displayJobResultJSON(job)
	}

	return displayJobResultTable(ctx, job)
}

// handleJobKill terminates a running job
func handleJobKill(ctx context.Context, saltClient client.SaltClient, jobID string) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Killing job", zap.String("job_id", jobID))

	err := saltClient.KillJob(ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to kill job: %w", err)
	}

	fmt.Printf("✅ Job %s has been terminated\n", jobID)
	logger.Info("Job killed successfully", zap.String("job_id", jobID))

	return nil
}

// handleJobWatch monitors a job in real-time
func handleJobWatch(ctx context.Context, saltClient client.SaltClient, jobID string) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Watching job progress", 
		zap.String("job_id", jobID),
		zap.Int("timeout", jobWatchTimeout))

	// Create context with timeout
	watchCtx, cancel := context.WithTimeout(ctx, time.Duration(jobWatchTimeout)*time.Second)
	defer cancel()

	return watchJobProgress(watchCtx, saltClient, jobID)
}

// watchJobProgress monitors job execution with real-time updates
func watchJobProgress(ctx context.Context, saltClient client.SaltClient, jobID string) error {
	logger := otelzap.Ctx(ctx)
	
	fmt.Printf("👀 Watching job %s\n", jobID)
	fmt.Printf("Press Ctrl+C to stop watching\n\n")
	
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	lastResults := make(map[string]interface{})
	
	for {
		select {
		case <-ctx.Done():
			fmt.Printf("\n⏰ Watch timeout or cancelled\n")
			return nil
		case <-ticker.C:
			job, err := saltClient.GetJob(ctx, jobID)
			if err != nil {
				logger.Warn("Failed to get job status during watch", zap.Error(err))
				continue
			}
			
			// Check for new results
			if job.Result != nil {
				for minionID, result := range job.Result {
					if _, seen := lastResults[minionID]; !seen {
						fmt.Printf("📨 %s: ", minionID)
						displayMinionJobResult(result)
						lastResults[minionID] = result
					}
				}
			}
			
			// Check if job is complete
			totalMinions := len(job.Minions)
			completedMinions := len(job.Result)
			missingMinions := len(job.Missing)
			
			if completedMinions >= (totalMinions - missingMinions) {
				fmt.Printf("\n✅ Job %s completed\n", jobID)
				fmt.Printf("📊 Final Summary:\n")
				fmt.Printf("   Total Minions: %d\n", totalMinions)
				fmt.Printf("   Completed: %d\n", completedMinions)
				fmt.Printf("   Missing: %d\n", missingMinions)
				return nil
			}
			
			// Show progress
			fmt.Printf("⏳ Progress: %d/%d minions completed\r", completedMinions, totalMinions-missingMinions)
		}
	}
}

// Display functions

func displayJobListJSON(jobs *client.JobList) error {
	jsonData, err := json.MarshalIndent(jobs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func displayJobListTable(ctx context.Context, jobs *client.JobList) error {
	if len(jobs.Jobs) == 0 {
		fmt.Println("📭 No jobs found")
		return nil
	}

	fmt.Printf("\n📋 Salt Jobs (Last %d)\n", len(jobs.Jobs))
	fmt.Printf("====================\n")
	fmt.Printf("%-20s %-15s %-25s %-10s %-s\n", "Job ID", "User", "Function", "Minions", "Start Time")
	fmt.Printf("%-20s %-15s %-25s %-10s %-s\n", "------", "----", "--------", "-------", "----------")

	for _, job := range jobs.Jobs {
		minionCount := len(job.Minions)
		startTime := job.StartTime
		if startTime == "" {
			startTime = "unknown"
		} else {
			// Try to parse and format the time
			if t, err := time.Parse(time.RFC3339, startTime); err == nil {
				startTime = t.Format("2006-01-02 15:04:05")
			}
		}
		
		// Truncate function name if too long
		function := job.Function
		if len(function) > 23 {
			function = function[:20] + "..."
		}
		
		fmt.Printf("%-20s %-15s %-25s %-10d %-s\n", 
			job.JobID, job.User, function, minionCount, startTime)
	}

	fmt.Printf("\n💡 Use 'eos salt job status <job-id>' for detailed information\n")
	return nil
}

func displayJobStatusJSON(job *client.JobResult) error {
	jsonData, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func displayJobStatusTable(ctx context.Context, job *client.JobResult) error {
	fmt.Printf("\n📊 Job Status: %s\n", job.JobID)
	fmt.Printf("====================\n")
	fmt.Printf("Function: %s\n", job.Function)
	fmt.Printf("Target: %s\n", job.Target)
	fmt.Printf("User: %s\n", job.User)
	fmt.Printf("Start Time: %s\n", job.StartTime)
	fmt.Printf("Target Minions: %d\n", len(job.Minions))
	fmt.Printf("Missing Minions: %d\n", len(job.Missing))
	
	if job.Result != nil {
		fmt.Printf("Completed Minions: %d\n", len(job.Result))
	} else {
		fmt.Printf("Completed Minions: 0\n")
	}

	// Show minion lists
	if len(job.Minions) > 0 {
		fmt.Printf("\n🎯 Target Minions:\n")
		for _, minion := range job.Minions {
			fmt.Printf("   • %s\n", minion)
		}
	}

	if len(job.Missing) > 0 {
		fmt.Printf("\n❌ Missing Minions:\n")
		for _, minion := range job.Missing {
			fmt.Printf("   • %s\n", minion)
		}
	}

	// Determine job status
	status := determineJobStatusFromResult(job)
	fmt.Printf("\n📈 Status: %s\n", status)

	return nil
}

func displayJobResultJSON(job *client.JobResult) error {
	result := map[string]interface{}{
		"job_id":   job.JobID,
		"function": job.Function,
		"results":  job.Result,
	}

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func displayJobResultTable(ctx context.Context, job *client.JobResult) error {
	fmt.Printf("\n📋 Job Results: %s\n", job.JobID)
	fmt.Printf("Function: %s\n", job.Function)
	fmt.Printf("=========================\n")

	if len(job.Result) == 0 {
		fmt.Printf("⚠️  No results available yet\n")
		fmt.Printf("Job may still be running or failed to start\n")
		return nil
	}

	for minionID, result := range job.Result {
		fmt.Printf("\n🖥️  Minion: %s\n", minionID)
		fmt.Printf("   Result: ")
		displayMinionJobResult(result)
	}

	return nil
}

func displayMinionJobResult(result interface{}) {
	switch v := result.(type) {
	case bool:
		if v {
			fmt.Printf("✅ Success\n")
		} else {
			fmt.Printf("❌ Failed\n")
		}
	case string:
		// Handle multi-line output
		lines := strings.Split(v, "\n")
		if len(lines) == 1 {
			fmt.Printf("%s\n", v)
		} else {
			fmt.Printf("\n")
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					fmt.Printf("      %s\n", line)
				}
			}
		}
	case map[string]interface{}:
		fmt.Printf("\n")
		for key, value := range v {
			if key == "retcode" {
				if code, ok := value.(float64); ok {
					if code == 0 {
						fmt.Printf("      %s: ✅ %v\n", key, value)
					} else {
						fmt.Printf("      %s: ❌ %v\n", key, value)
					}
				} else {
					fmt.Printf("      %s: %v\n", key, value)
				}
			} else {
				fmt.Printf("      %s: %v\n", key, value)
			}
		}
	default:
		fmt.Printf("%v\n", v)
	}
}

func determineJobStatusFromResult(job *client.JobResult) string {
	totalMinions := len(job.Minions)
	missingMinions := len(job.Missing)
	expectedMinions := totalMinions - missingMinions
	
	if job.Result == nil {
		if missingMinions == totalMinions {
			return "❌ FAILED (no minions available)"
		}
		return "⏳ RUNNING"
	}
	
	completedMinions := len(job.Result)
	
	if completedMinions < expectedMinions {
		return fmt.Sprintf("⏳ IN PROGRESS (%d/%d completed)", completedMinions, expectedMinions)
	}
	
	// Check for failures
	hasFailures := false
	for _, result := range job.Result {
		if retcode, ok := result["retcode"].(float64); ok && retcode != 0 {
			hasFailures = true
			break
		}
	}
	
	if hasFailures {
		return "❌ COMPLETED WITH ERRORS"
	}
	
	return "✅ COMPLETED SUCCESSFULLY"
}