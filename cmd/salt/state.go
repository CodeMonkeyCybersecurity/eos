// cmd/salt/state.go
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
	testMode    bool
	pillarData  []string
	refreshPillar bool
	noCache     bool
	stateOutput string
)

// SaltStateCmd manages Salt states on minions
var SaltStateCmd = &cobra.Command{
	Use:   "state [target] [function] [args...]",
	Short: "Execute Salt states on minions",
	Long: `Execute Salt states on specified minions.

Salt states are declarative configurations that ensure minions are in the
desired state. States are idempotent - they only make changes when needed
to bring the system to the desired state.

Examples:
  eos salt state '*' state.apply                    # Apply highstate
  eos salt state 'web*' state.apply nginx          # Apply nginx state
  eos salt state 'db*' state.apply mysql pillar='{"mysql": {"root_password": "secret"}}'
  eos salt state '*' state.apply --test            # Test state application (dry run)
  eos salt state 'app*' state.single pkg.installed name=git
  eos salt state '*' state.show_sls nginx          # Show state definition
  
Common State Functions:
  state.apply        - Apply specified states (or highstate if no state specified)
  state.single       - Apply a single state function
  state.test         - Test state application without making changes
  state.show_sls     - Show the state file content
  state.show_top     - Show the top file content
  state.show_highstate - Show what the highstate would do
  state.sls_exists   - Check if state file exists
  
Pillar Data:
  Use --pillar key=value or --pillar-file to pass pillar data to states.
  Multiple --pillar flags can be used for multiple key-value pairs.`,

	Args: cobra.MinimumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		target := args[0]
		function := "state.apply"
		stateArgs := []string{}
		
		if len(args) > 1 {
			function = args[1]
			stateArgs = args[2:]
		}
		
		logger.Info("Starting Salt state operation",
			zap.String("target", target),
			zap.String("function", function),
			zap.Strings("args", stateArgs),
			zap.Bool("test_mode", testMode || dryRun),
			zap.String("target_type", targetType))

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
		pillar, err := parsePillarData(pillarData)
		if err != nil {
			return fmt.Errorf("invalid pillar data: %w", err)
		}

		// Execute state
		logger.Info("Executing Salt state",
			zap.String("target", target),
			zap.String("function", function))
		
		req := &client.StateRequest{
			Client:     client.ClientTypeLocal,
			Target:     target,
			Function:   function,
			Args:       stateArgs,
			TargetType: targetType,
			Pillar:     pillar,
			Test:       testMode || dryRun,
			Concurrent: concurrent > 0,
		}

		startTime := time.Now()
		response, err := saltClient.RunState(rc.Ctx, req)
		if err != nil {
			return fmt.Errorf("state execution failed: %w", err)
		}
		duration := time.Since(startTime)

		// Process and display results
		logger.Info("Processing state results",
			zap.String("job_id", response.JobID),
			zap.Duration("duration", duration))

		return displayStateResults(rc.Ctx, response, duration, target, function, testMode || dryRun)
	}),
}

func init() {
	// Add state-specific flags
	SaltStateCmd.Flags().BoolVarP(&testMode, "test", "t", false, "Test mode - show what would be done without making changes")
	SaltStateCmd.Flags().StringSliceVar(&pillarData, "pillar", []string{}, "Pillar data in key=value format (can be specified multiple times)")
	SaltStateCmd.Flags().BoolVar(&refreshPillar, "refresh-pillar", false, "Refresh pillar data before state execution")
	SaltStateCmd.Flags().BoolVar(&noCache, "no-cache", false, "Don't use cached pillar/grains data")
	SaltStateCmd.Flags().StringVar(&stateOutput, "state-output", "mixed", "State output format (full, terse, mixed, changes)")
}

// parsePillarData converts key=value strings to pillar map
func parsePillarData(pillarArgs []string) (map[string]interface{}, error) {
	pillar := make(map[string]interface{})
	
	for _, pillarArg := range pillarArgs {
		// Simple key=value parsing
		parts := strings.SplitN(pillarArg, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid pillar format: %s (expected key=value)", pillarArg)
		}
		
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		
		// Try to parse as JSON for complex values
		var parsedValue interface{}
		if err := json.Unmarshal([]byte(value), &parsedValue); err != nil {
			// If JSON parsing fails, treat as string
			parsedValue = value
		}
		
		pillar[key] = parsedValue
	}
	
	return pillar, nil
}

// displayStateResults processes and displays state execution results
func displayStateResults(ctx context.Context, response *client.StateResponse, duration time.Duration, target, function string, isTest bool) error {
	if jsonOutput {
		return displayStateResultsJSON(response, duration, target, function, isTest)
	}

	return displayStateResultsTable(ctx, response, duration, target, function, isTest)
}

// displayStateResultsJSON displays results in JSON format
func displayStateResultsJSON(response *client.StateResponse, duration time.Duration, target, function string, isTest bool) error {
	result := map[string]interface{}{
		"target":   target,
		"function": function,
		"test":     isTest,
		"job_id":   response.JobID,
		"duration": duration.String(),
		"results":  response.Return,
	}

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(jsonData))
	return nil
}

// displayStateResultsTable displays results in table format
func displayStateResultsTable(ctx context.Context, response *client.StateResponse, duration time.Duration, target, function string, isTest bool) error {
	
	if len(response.Return) == 0 {
		fmt.Println("❌ No minions responded to state execution")
		return nil
	}

	// Collect and analyze results
	minionResults := make(map[string]*MinionStateResult)
	
	for _, returnData := range response.Return {
		for minionID, minionStateData := range returnData {
			if _, exists := minionResults[minionID]; !exists {
				minionResults[minionID] = &MinionStateResult{
					MinionID:    minionID,
					States:      make(map[string]*client.StateResult),
					TotalStates: 0,
					Succeeded:   0,
					Failed:      0,
					Changed:     0,
					Duration:    0,
				}
			}
			
			result := minionResults[minionID]
			// minionStateData is a *StateResult, but we need to treat it as a collection of states
			// For simplicity, we'll use the minion ID as the state ID
			stateID := minionID + "_state"
			result.States[stateID] = minionStateData
			result.TotalStates++
			result.Duration += minionStateData.Duration
			
			if minionStateData.Result != nil {
				if *minionStateData.Result {
					result.Succeeded++
					if len(minionStateData.Changes) > 0 {
						result.Changed++
					}
				} else {
					result.Failed++
				}
			}
		}
	}

	// Display results
	modeStr := "Execution"
	if isTest {
		modeStr = "Test"
	}
	
	fmt.Printf("\n🔧 Salt State %s Results\n", modeStr)
	fmt.Printf("==========================\n")
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("Function: %s\n", function)
	fmt.Printf("Job ID: %s\n", response.JobID)
	fmt.Printf("Duration: %s\n", duration)
	fmt.Printf("Minions: %d\n", len(minionResults))
	
	if isTest {
		fmt.Printf("⚠️  TEST MODE - No changes were made\n")
	}
	
	// Display per-minion results
	for minionID, result := range minionResults {
		fmt.Printf("\n📋 Minion: %s\n", minionID)
		fmt.Printf("   States: %d total, %d succeeded, %d failed, %d changed\n",
			result.TotalStates, result.Succeeded, result.Failed, result.Changed)
		fmt.Printf("   Duration: %.2fs\n", result.Duration)
		
		if result.Failed > 0 {
			fmt.Printf("   Status: ❌ FAILED\n")
		} else if result.Changed > 0 {
			fmt.Printf("   Status: ✅ CHANGED\n")
		} else {
			fmt.Printf("   Status: ✅ SUCCEEDED (no changes needed)\n")
		}
		
		// Show detailed state results based on output format
		if stateOutput == "full" || stateOutput == "changes" && result.Changed > 0 {
			displayDetailedStateResults(result.States, stateOutput == "changes")
		} else if stateOutput == "terse" {
			displayTerseStateResults(result.States)
		} else {
			// Mixed format - show changes and failures
			displayMixedStateResults(result.States)
		}
	}

	// Summary statistics
	totalStates := 0
	totalSucceeded := 0
	totalFailed := 0
	totalChanged := 0
	
	for _, result := range minionResults {
		totalStates += result.TotalStates
		totalSucceeded += result.Succeeded
		totalFailed += result.Failed
		totalChanged += result.Changed
	}
	
	fmt.Printf("\n📊 Summary:\n")
	fmt.Printf("   Total States: %d\n", totalStates)
	fmt.Printf("   Succeeded: %d\n", totalSucceeded)
	fmt.Printf("   Failed: %d\n", totalFailed)
	fmt.Printf("   Changed: %d\n", totalChanged)
	
	if totalFailed > 0 {
		fmt.Printf("   Overall Status: ❌ FAILED\n")
	} else if totalChanged > 0 {
		fmt.Printf("   Overall Status: ✅ CHANGED\n")
	} else {
		fmt.Printf("   Overall Status: ✅ SUCCEEDED\n")
	}

	// Log summary
	logger := otelzap.Ctx(ctx)
	logger.Info("State execution completed",
		zap.String("target", target),
		zap.String("function", function),
		zap.String("job_id", response.JobID),
		zap.Duration("duration", duration),
		zap.Int("minions", len(minionResults)),
		zap.Int("total_states", totalStates),
		zap.Int("succeeded", totalSucceeded),
		zap.Int("failed", totalFailed),
		zap.Int("changed", totalChanged),
		zap.Bool("test_mode", isTest))

	return nil
}

// MinionStateResult aggregates state results for a single minion
type MinionStateResult struct {
	MinionID    string
	States      map[string]*client.StateResult
	TotalStates int
	Succeeded   int
	Failed      int
	Changed     int
	Duration    float64
}

// displayDetailedStateResults shows full state details
func displayDetailedStateResults(states map[string]*client.StateResult, changesOnly bool) {
	for stateID, state := range states {
		if changesOnly && len(state.Changes) == 0 {
			continue
		}
		
		fmt.Printf("\n     State: %s\n", stateID)
		fmt.Printf("       Name: %s\n", state.Name)
		fmt.Printf("       Function: %s\n", state.SLS)
		
		if state.Result != nil {
			if *state.Result {
				fmt.Printf("       Result: ✅ Success\n")
			} else {
				fmt.Printf("       Result: ❌ Failed\n")
			}
		} else {
			fmt.Printf("       Result: ⚠️  Unknown\n")
		}
		
		fmt.Printf("       Duration: %.3fs\n", state.Duration)
		
		if state.Comment != "" {
			fmt.Printf("       Comment: %s\n", state.Comment)
		}
		
		if len(state.Changes) > 0 {
			fmt.Printf("       Changes:\n")
			for key, change := range state.Changes {
				fmt.Printf("         %s: %v\n", key, change)
			}
		}
	}
}

// displayTerseStateResults shows minimal state information
func displayTerseStateResults(states map[string]*client.StateResult) {
	for stateID, state := range states {
		status := "❓"
		if state.Result != nil {
			if *state.Result {
				if len(state.Changes) > 0 {
					status = "✅"
				} else {
					status = "⚪"
				}
			} else {
				status = "❌"
			}
		}
		fmt.Printf("     %s %s\n", status, stateID)
	}
}

// displayMixedStateResults shows changes and failures
func displayMixedStateResults(states map[string]*client.StateResult) {
	for stateID, state := range states {
		// Show failed states
		if state.Result != nil && !*state.Result {
			fmt.Printf("\n     ❌ %s: FAILED\n", stateID)
			if state.Comment != "" {
				fmt.Printf("        %s\n", state.Comment)
			}
		}
		// Show changed states
		if state.Result != nil && *state.Result && len(state.Changes) > 0 {
			fmt.Printf("\n     ✅ %s: CHANGED\n", stateID)
			if state.Comment != "" {
				fmt.Printf("        %s\n", state.Comment)
			}
			// Show summary of changes
			changeCount := len(state.Changes)
			if changeCount > 0 {
				fmt.Printf("        %d change(s) made\n", changeCount)
			}
		}
	}
}