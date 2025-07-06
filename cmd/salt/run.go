// cmd/salt/run.go
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

// SaltRunCmd executes Salt commands on minions
var SaltRunCmd = &cobra.Command{
	Use:   "run [target] [function] [args...]",
	Short: "Execute Salt commands on minions",
	Long: `Execute Salt commands on specified minions.

This command runs Salt execution modules on the target minions and returns
the results. It's the primary way to execute commands, install packages,
manage services, and perform other operations on minions.

Examples:
  eos salt run '*' test.ping                    # Test connectivity
  eos salt run 'web*' cmd.run 'uptime'         # Run shell command
  eos salt run 'db*' pkg.install 'mysql-server' # Install package
  eos salt run 'app*' service.start 'nginx'    # Start service
  eos salt run '*' grains.item 'os'            # Get OS grain
  eos salt run '*' pillar.get 'users'          # Get pillar data
  
Common Functions:
  test.ping          - Test minion connectivity
  cmd.run            - Execute shell commands
  pkg.install        - Install packages
  pkg.remove         - Remove packages
  service.start      - Start services
  service.stop       - Stop services
  service.restart    - Restart services
  grains.items       - Get all grains
  grains.item        - Get specific grain
  pillar.items       - Get all pillar data
  pillar.get         - Get specific pillar value
  file.managed       - Manage files
  user.present       - Ensure user exists
  group.present      - Ensure group exists`,

	Args: cobra.MinimumNArgs(2),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		target := args[0]
		function := args[1]
		functionArgs := args[2:]
		
		logger.Info("Starting Salt run operation",
			zap.String("target", target),
			zap.String("function", function),
			zap.Strings("args", functionArgs),
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

		// Execute command
		logger.Info("Executing Salt command",
			zap.String("target", target),
			zap.String("function", function))
		
		req := &client.CommandRequest{
			Client:     client.ClientTypeLocal,
			Target:     target,
			Function:   function,
			Args:       functionArgs,
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
			return fmt.Errorf("command execution failed: %w", err)
		}
		duration := time.Since(startTime)

		// Process and display results
		logger.Info("Processing command results",
			zap.String("job_id", response.JobID),
			zap.Duration("duration", duration))

		return displayRunResults(rc.Ctx, response, duration, target, function)
	}),
}

func init() {
	// Add run-specific flags
	SaltRunCmd.Flags().IntVar(&concurrent, "concurrent", 0, "Maximum concurrent executions")
	SaltRunCmd.Flags().StringVar(&batch, "batch", "", "Batch size for execution")
}

// displayRunResults processes and displays command execution results
func displayRunResults(ctx context.Context, response *client.CommandResponse, duration time.Duration, target, function string) error {
	if jsonOutput {
		return displayRunResultsJSON(response, duration, target, function)
	}

	return displayRunResultsTable(ctx, response, duration, target, function)
}

// displayRunResultsJSON displays results in JSON format
func displayRunResultsJSON(response *client.CommandResponse, duration time.Duration, target, function string) error {
	result := map[string]interface{}{
		"target":   target,
		"function": function,
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

// displayRunResultsTable displays results in table format
func displayRunResultsTable(ctx context.Context, response *client.CommandResponse, duration time.Duration, target, function string) error {
	
	if len(response.Return) == 0 {
		fmt.Println("❌ No minions responded to command")
		return nil
	}

	// Collect minion responses
	successfulMinions := make(map[string]interface{})
	failedMinions := make(map[string]interface{})
	
	for _, returnData := range response.Return {
		for minionID, result := range returnData {
			// Check if result indicates an error
			if isErrorResult(result) {
				failedMinions[minionID] = result
			} else {
				successfulMinions[minionID] = result
			}
		}
	}

	totalMinions := len(successfulMinions) + len(failedMinions)
	
	// Display summary
	fmt.Printf("\n⚡ Salt Command Results\n")
	fmt.Printf("======================\n")
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("Function: %s\n", function)
	fmt.Printf("Job ID: %s\n", response.JobID)
	fmt.Printf("Duration: %s\n", duration)
	fmt.Printf("Total Minions: %d\n", totalMinions)
	fmt.Printf("Successful: %d\n", len(successfulMinions))
	fmt.Printf("Failed: %d\n", len(failedMinions))
	
	// Display successful results
	if len(successfulMinions) > 0 {
		fmt.Printf("\n✅ Successful Results (%d):\n", len(successfulMinions))
		for minionID, result := range successfulMinions {
			fmt.Printf("\n%s:\n", minionID)
			displayMinionResult(result, "  ")
		}
	}
	
	// Display failed results
	if len(failedMinions) > 0 {
		fmt.Printf("\n❌ Failed Results (%d):\n", len(failedMinions))
		for minionID, result := range failedMinions {
			fmt.Printf("\n%s:\n", minionID)
			displayMinionResult(result, "  ")
		}
	}

	if len(successfulMinions) == 0 && len(failedMinions) == 0 {
		fmt.Printf("\n⚠️  No minions responded to command\n")
		fmt.Printf("Check target specification and minion connectivity\n")
	}

	// Log detailed results
	logger := otelzap.Ctx(ctx)
	logger.Info("Command execution completed",
		zap.String("target", target),
		zap.String("function", function),
		zap.String("job_id", response.JobID),
		zap.Duration("duration", duration),
		zap.Int("total_minions", totalMinions),
		zap.Int("successful", len(successfulMinions)),
		zap.Int("failed", len(failedMinions)))

	return nil
}

// isErrorResult checks if a result indicates an error
func isErrorResult(result interface{}) bool {
	if resultStr, ok := result.(string); ok {
		// Check for common error patterns
		if strings.Contains(resultStr, "ERROR") ||
		   strings.Contains(resultStr, "Failed") ||
		   strings.Contains(resultStr, "No such file") ||
		   strings.Contains(resultStr, "Permission denied") ||
		   strings.Contains(resultStr, "Command not found") {
			return true
		}
	}
	
	// Check for error maps
	if resultMap, ok := result.(map[string]interface{}); ok {
		if _, hasError := resultMap["error"]; hasError {
			return true
		}
		if retcode, ok := resultMap["retcode"].(float64); ok && retcode != 0 {
			return true
		}
	}
	
	return false
}

// displayMinionResult displays a single minion's result with proper formatting
func displayMinionResult(result interface{}, indent string) {
	switch v := result.(type) {
	case string:
		// Handle multi-line strings
		lines := strings.Split(v, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				fmt.Printf("%s%s\n", indent, line)
			}
		}
	case map[string]interface{}:
		// Handle structured results
		for key, value := range v {
			fmt.Printf("%s%s: ", indent, key)
			if valueStr, ok := value.(string); ok {
				if strings.Contains(valueStr, "\n") {
					fmt.Println()
					lines := strings.Split(valueStr, "\n")
					for _, line := range lines {
						if strings.TrimSpace(line) != "" {
							fmt.Printf("%s  %s\n", indent, line)
						}
					}
				} else {
					fmt.Printf("%s\n", valueStr)
				}
			} else {
				fmt.Printf("%v\n", value)
			}
		}
	case []interface{}:
		// Handle array results
		for i, item := range v {
			fmt.Printf("%s[%d]: %v\n", indent, i, item)
		}
	case bool:
		if v {
			fmt.Printf("%s✅ True\n", indent)
		} else {
			fmt.Printf("%s❌ False\n", indent)
		}
	case nil:
		fmt.Printf("%s(null)\n", indent)
	default:
		fmt.Printf("%s%v\n", indent, v)
	}
}