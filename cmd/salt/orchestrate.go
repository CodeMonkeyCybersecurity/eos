// cmd/salt/orchestrate.go
package salt

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt/client"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	orchestratePillar []string
	orchestrateWatch  bool
	orchestrateShow   bool
)

// SaltOrchestrateCmd executes Salt orchestration files
var SaltOrchestrateCmd = &cobra.Command{
	Use:   "orchestrate [orchestration] [args...]",
	Short: "Execute Salt orchestration files for complex infrastructure operations",
	Long: `Execute Salt orchestration files to coordinate complex infrastructure operations.

Orchestration files define high-level workflows that coordinate multiple Salt states
across different minions, enabling complex infrastructure deployments, updates,
and configurations with proper dependency management and error handling.

Examples:
  eos salt orchestrate deploy-vault                          # Deploy Vault cluster
  eos salt orchestrate hashicorp-stack pillar='{"env":"prod"}' # Deploy HashiCorp stack
  eos salt orchestrate infrastructure-refresh --watch        # Watch orchestration progress
  eos salt orchestrate rolling-update --show                 # Show orchestration without executing
  eos salt orchestrate disaster-recovery --pillar env=prod --pillar region=us-west-2
  
Common Orchestration Files:
  deploy-vault           - Deploy and configure HashiCorp Vault cluster
  deploy-consul          - Deploy and configure Consul cluster
  hashicorp-stack        - Deploy complete HashiCorp infrastructure
  infrastructure-refresh - Rolling infrastructure update
  disaster-recovery      - Execute disaster recovery procedures
  security-hardening     - Apply security hardening across infrastructure
  scaling-operations     - Scale infrastructure components
  
Orchestration vs State:
  - States: Configure individual minions
  - Orchestration: Coordinate multiple states across minions with dependencies
  
The orchestration engine supports:
  - Multi-minion coordination
  - Complex dependency graphs
  - Parallel and sequential execution
  - Error handling and rollback
  - Real-time progress monitoring`,

	Args: cobra.MinimumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		orchestrationName := args[0]
		orchestrationArgs := args[1:]
		
		logger.Info("Starting Salt orchestration",
			zap.String("orchestration", orchestrationName),
			zap.Strings("args", orchestrationArgs),
			zap.Bool("watch", orchestrateWatch),
			zap.Bool("show", orchestrateShow))

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
		defer saltClient.Logout(rc.Ctx)

		// Parse pillar data
		pillar, err := parsePillarData(orchestratePillar)
		if err != nil {
			return fmt.Errorf("invalid pillar data: %w", err)
		}

		// Execute orchestration
		logger.Info("Executing Salt orchestration",
			zap.String("orchestration", orchestrationName))
		
		req := &client.OrchestrationRequest{
			Client:   client.ClientTypeRunner,
			Function: "state.orchestrate",
			Mods:     []string{orchestrationName},
			Pillar:   pillar,
		}

		// Add additional arguments as kwargs
		if len(orchestrationArgs) > 0 {
			if req.Kwargs == nil {
				req.Kwargs = make(map[string]interface{})
			}
			for i, arg := range orchestrationArgs {
				req.Kwargs[fmt.Sprintf("arg_%d", i)] = arg
			}
		}

		// Handle show mode (test what would be executed)
		if orchestrateShow {
			req.Kwargs["test"] = true
		}

		startTime := time.Now()
		response, err := saltClient.RunOrchestrate(rc.Ctx, req)
		if err != nil {
			return fmt.Errorf("orchestration execution failed: %w", err)
		}
		duration := time.Since(startTime)

		// Handle watch mode
		if orchestrateWatch && response.JobID != "" {
			logger.Info("Watching orchestration progress", zap.String("job_id", response.JobID))
			return watchOrchestrationJob(rc.Ctx, saltClient, response.JobID)
		}

		// Process and display results
		logger.Info("Processing orchestration results",
			zap.String("job_id", response.JobID),
			zap.Duration("duration", duration))

		return displayOrchestrationResults(rc.Ctx, response, duration, orchestrationName, orchestrateShow)
	}),
}

func init() {
	// Add orchestrate-specific flags
	SaltOrchestrateCmd.Flags().StringSliceVar(&orchestratePillar, "pillar", []string{}, "Pillar data in key=value format")
	SaltOrchestrateCmd.Flags().BoolVarP(&orchestrateWatch, "watch", "w", false, "Watch orchestration progress in real-time")
	SaltOrchestrateCmd.Flags().BoolVar(&orchestrateShow, "show", false, "Show what would be executed without making changes")
}

// watchOrchestrationJob monitors an orchestration job in real-time
func watchOrchestrationJob(ctx context.Context, saltClient client.SaltClient, jobID string) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Starting orchestration job monitoring", zap.String("job_id", jobID))
	
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	timeout := time.NewTimer(30 * time.Minute)
	defer timeout.Stop()
	
	lastStatus := "unknown"
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			fmt.Printf("\n⏰ Orchestration monitoring timeout reached\n")
			return nil
		case <-ticker.C:
			job, err := saltClient.GetJob(ctx, jobID)
			if err != nil {
				logger.Warn("Failed to get job status", zap.Error(err))
				continue
			}
			
			// Determine job status
			status := determineJobStatus(job)
			
			// Only print status changes
			if status != lastStatus {
				fmt.Printf("\n📊 Orchestration Status: %s\n", status)
				
				if len(job.Minions) > 0 {
					fmt.Printf("Target Minions: %v\n", job.Minions)
				}
				
				if len(job.Missing) > 0 {
					fmt.Printf("Missing Minions: %v\n", job.Missing)
				}
				
				lastStatus = status
			}
			
			// Check if job is complete
			if status == "✅ COMPLETED" || status == "❌ FAILED" {
				fmt.Printf("\nOrchestration finished with status: %s\n", status)
				
				// Display final results
				if job.Result != nil {
					fmt.Printf("\n📋 Final Results:\n")
					for minionID, result := range job.Result {
						fmt.Printf("  %s: %v\n", minionID, result)
					}
				}
				
				return nil
			}
			
			// Show progress indicator
			fmt.Print(".")
		}
	}
}

// determineJobStatus analyzes job data to determine current status
func determineJobStatus(job *client.JobResult) string {
	if job == nil {
		return "❓ UNKNOWN"
	}
	
	totalMinions := len(job.Minions)
	missingMinions := len(job.Missing)
	
	if job.Result == nil && missingMinions == 0 {
		return "⏳ RUNNING"
	}
	
	if job.Result == nil && missingMinions > 0 {
		return "⚠️ WAITING FOR MINIONS"
	}
	
	completedMinions := len(job.Result)
	
	if completedMinions == 0 {
		return "🚀 STARTING"
	}
	
	if completedMinions < totalMinions-missingMinions {
		return fmt.Sprintf("⏳ IN PROGRESS (%d/%d)", completedMinions, totalMinions-missingMinions)
	}
	
	// Check for failures in results
	hasFailures := false
	for _, result := range job.Result {
		// result is already map[string]interface{}
		// Look for failure indicators
		if success, ok := result["success"].(bool); ok && !success {
			hasFailures = true
			break
		}
		if retcode, ok := result["retcode"].(float64); ok && retcode != 0 {
			hasFailures = true
			break
		}
	}
	
	if hasFailures {
		return "❌ FAILED"
	}
	
	return "✅ COMPLETED"
}

// displayOrchestrationResults processes and displays orchestration results
func displayOrchestrationResults(ctx context.Context, response *client.OrchestrationResponse, duration time.Duration, orchestrationName string, isShow bool) error {
	if jsonOutput {
		return displayOrchestrationResultsJSON(response, duration, orchestrationName, isShow)
	}

	return displayOrchestrationResultsTable(ctx, response, duration, orchestrationName, isShow)
}

// displayOrchestrationResultsJSON displays results in JSON format
func displayOrchestrationResultsJSON(response *client.OrchestrationResponse, duration time.Duration, orchestrationName string, isShow bool) error {
	result := map[string]interface{}{
		"orchestration": orchestrationName,
		"show_mode":     isShow,
		"job_id":        response.JobID,
		"duration":      duration.String(),
		"results":       response.Return,
	}

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(jsonData))
	return nil
}

// displayOrchestrationResultsTable displays results in table format
func displayOrchestrationResultsTable(ctx context.Context, response *client.OrchestrationResponse, duration time.Duration, orchestrationName string, isShow bool) error {
	logger := otelzap.Ctx(ctx)
	
	if len(response.Return) == 0 {
		fmt.Println("❌ No orchestration results received")
		return nil
	}

	// Collect orchestration step results
	stepResults := make(map[string]*client.OrchestrationResult)
	totalSteps := 0
	successfulSteps := 0
	failedSteps := 0
	
	for _, returnData := range response.Return {
		for stepID, result := range returnData {
			stepResults[stepID] = result
			totalSteps++
			
			if result.Result {
				successfulSteps++
			} else {
				failedSteps++
			}
		}
	}

	// Display results
	modeStr := "Execution"
	if isShow {
		modeStr = "Preview"
	}
	
	fmt.Printf("\n🎭 Salt Orchestration %s Results\n", modeStr)
	fmt.Printf("=======================================\n")
	fmt.Printf("Orchestration: %s\n", orchestrationName)
	fmt.Printf("Job ID: %s\n", response.JobID)
	fmt.Printf("Duration: %s\n", duration)
	fmt.Printf("Total Steps: %d\n", totalSteps)
	fmt.Printf("Successful: %d\n", successfulSteps)
	fmt.Printf("Failed: %d\n", failedSteps)
	
	if isShow {
		fmt.Printf("⚠️  PREVIEW MODE - No changes were made\n")
	}
	
	// Display step-by-step results
	fmt.Printf("\n📋 Orchestration Steps:\n")
	for stepID, result := range stepResults {
		status := "✅"
		if !result.Result {
			status = "❌"
		}
		
		fmt.Printf("\n%s Step: %s\n", status, stepID)
		fmt.Printf("   Name: %s\n", result.Name)
		fmt.Printf("   Duration: %.2fs\n", result.Duration)
		
		if result.Comment != "" {
			fmt.Printf("   Comment: %s\n", result.Comment)
		}
		
		if len(result.Changes) > 0 {
			fmt.Printf("   Changes:\n")
			for key, change := range result.Changes {
				fmt.Printf("     %s: %v\n", key, change)
			}
		}
		
		if len(result.Data) > 0 {
			fmt.Printf("   Data:\n")
			for key, value := range result.Data {
				if key != "changes" { // Don't duplicate changes
					fmt.Printf("     %s: %v\n", key, value)
				}
			}
		}
	}

	// Summary
	fmt.Printf("\n📊 Summary:\n")
	if failedSteps > 0 {
		fmt.Printf("   Overall Status: ❌ FAILED\n")
		fmt.Printf("   ⚠️  %d step(s) failed - check logs for details\n", failedSteps)
	} else if successfulSteps > 0 {
		fmt.Printf("   Overall Status: ✅ SUCCEEDED\n")
		fmt.Printf("   🎉 All %d step(s) completed successfully\n", successfulSteps)
	} else {
		fmt.Printf("   Overall Status: ⚠️  NO STEPS EXECUTED\n")
	}

	// Log summary
	logger.Info("Orchestration execution completed",
		zap.String("orchestration", orchestrationName),
		zap.String("job_id", response.JobID),
		zap.Duration("duration", duration),
		zap.Int("total_steps", totalSteps),
		zap.Int("successful", successfulSteps),
		zap.Int("failed", failedSteps),
		zap.Bool("show_mode", isShow))

	return nil
}