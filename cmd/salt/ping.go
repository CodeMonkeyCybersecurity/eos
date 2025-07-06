// cmd/salt/ping.go
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

// SaltPingCmd pings Salt minions
var SaltPingCmd = &cobra.Command{
	Use:   "ping [target]",
	Short: "Ping Salt minions to test connectivity",
	Long: `Ping Salt minions to test connectivity and responsiveness.

This command sends a test.ping to the specified minions and reports
which minions are responsive. It's useful for checking minion health
and connectivity before running other operations.

Examples:
  eos salt ping '*'              # Ping all minions
  eos salt ping 'web*'           # Ping web servers
  eos salt ping 'web01,web02'    # Ping specific minions (list target type)
  eos salt ping 'os:Ubuntu' --target-type grain  # Ping Ubuntu minions via grain
  
Target Types:
  glob     - Shell-style wildcards (default)
  pcre     - Perl-compatible regular expressions
  list     - Comma-separated list of minion IDs
  grain    - Match based on grains data
  pillar   - Match based on pillar data
  nodegroup - Match based on nodegroup
  range    - Match based on range expressions
  compound - Complex expressions combining multiple target types
  ipcidr   - Match based on IP/CIDR ranges`,

	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		target := args[0]
		
		logger.Info("Starting Salt ping operation",
			zap.String("target", target),
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

		// Execute ping command
		logger.Info("Executing ping command", zap.String("target", target))
		
		req := &client.CommandRequest{
			Client:     client.ClientTypeLocal,
			Target:     target,
			Function:   client.FunctionTest,
			TargetType: targetType,
		}

		if concurrent > 0 {
			req.Kwargs = map[string]interface{}{
				"concurrent": concurrent,
			}
		}

		if batch != "" {
			req.BatchSize = batch
		}

		startTime := time.Now()
		response, err := saltClient.RunCommand(rc.Ctx, req)
		if err != nil {
			return fmt.Errorf("ping command failed: %w", err)
		}
		duration := time.Since(startTime)

		// Process and display results
		logger.Info("Processing ping results",
			zap.String("job_id", response.JobID),
			zap.Duration("duration", duration))

		return displayPingResults(rc.Ctx, response, duration)
	}),
}

func init() {
	// Add ping-specific flags
	SaltPingCmd.Flags().IntVar(&concurrent, "concurrent", 0, "Maximum concurrent ping operations")
	SaltPingCmd.Flags().StringVar(&batch, "batch", "", "Batch size for ping operations")
}

// displayPingResults processes and displays ping command results
func displayPingResults(ctx context.Context, response *client.CommandResponse, duration time.Duration) error {
	if jsonOutput {
		return displayPingResultsJSON(response, duration)
	}

	return displayPingResultsTable(ctx, response, duration)
}

// displayPingResultsJSON displays results in JSON format
func displayPingResultsJSON(response *client.CommandResponse, duration time.Duration) error {
	result := map[string]interface{}{
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

// displayPingResultsTable displays results in table format
func displayPingResultsTable(ctx context.Context, response *client.CommandResponse, duration time.Duration) error {
	
	if len(response.Return) == 0 {
		fmt.Println("❌ No minions responded to ping")
		return nil
	}

	// Collect minion responses
	successfulMinions := make([]string, 0)
	failedMinions := make([]string, 0)
	
	for _, returnData := range response.Return {
		for minionID, result := range returnData {
			if success, ok := result.(bool); ok && success {
				successfulMinions = append(successfulMinions, minionID)
			} else {
				failedMinions = append(failedMinions, minionID)
			}
		}
	}

	totalMinions := len(successfulMinions) + len(failedMinions)
	
	// Display summary
	fmt.Printf("\n🏓 Salt Ping Results\n")
	fmt.Printf("==================\n")
	fmt.Printf("Job ID: %s\n", response.JobID)
	fmt.Printf("Duration: %s\n", duration)
	fmt.Printf("Total Minions: %d\n", totalMinions)
	fmt.Printf("Successful: %d\n", len(successfulMinions))
	fmt.Printf("Failed: %d\n", len(failedMinions))
	
	if len(successfulMinions) > 0 {
		fmt.Printf("\n✅ Responsive Minions (%d):\n", len(successfulMinions))
		for _, minionID := range successfulMinions {
			fmt.Printf("   • %s\n", minionID)
		}
	}
	
	if len(failedMinions) > 0 {
		fmt.Printf("\n❌ Unresponsive Minions (%d):\n", len(failedMinions))
		for _, minionID := range failedMinions {
			fmt.Printf("   • %s\n", minionID)
		}
	}

	if len(successfulMinions) == 0 {
		fmt.Printf("\n⚠️  No minions responded to ping\n")
		fmt.Printf("Check minion connectivity and Salt master status\n")
	}

	// Log detailed results
	logger := otelzap.Ctx(ctx)
	logger.Info("Ping operation completed",
		zap.String("job_id", response.JobID),
		zap.Duration("duration", duration),
		zap.Int("total_minions", totalMinions),
		zap.Int("successful", len(successfulMinions)),
		zap.Int("failed", len(failedMinions)),
		zap.Strings("successful_minions", successfulMinions),
		zap.Strings("failed_minions", failedMinions))

	return nil
}