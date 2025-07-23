// package saltstack provides integration with Salt Stack for secure infrastructure management
package saltstack

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ClientInterface defines the interface for Salt Stack operations
type ClientInterface interface {
	StateApply(ctx context.Context, target string, state string, pillar map[string]interface{}) error
	TestPing(ctx context.Context, target string) (bool, error)
	GrainGet(ctx context.Context, target string, grain string) (map[string]interface{}, error)
	CmdRun(ctx context.Context, target string, command string) (string, error)
	CheckMinion(ctx context.Context, minion string) (bool, error)
	IsAPIAvailable(ctx context.Context) bool
}

// Client provides Salt Stack operations
type Client struct {
	logger otelzap.LoggerWithCtx
}

// NewClient creates a new Salt Stack client
func NewClient(logger otelzap.LoggerWithCtx) *Client {
	return &Client{
		logger: logger,
	}
}

// StateApply applies a Salt state
func (c *Client) StateApply(ctx context.Context, target string, state string, pillar map[string]interface{}) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Applying Salt state",
		zap.String("target", target),
		zap.String("state", state))

	args := []string{target, "state.apply", state}

	if len(pillar) > 0 {
		pillarJSON, err := json.Marshal(pillar)
		if err != nil {
			return fmt.Errorf("marshaling pillar data: %w", err)
		}
		args = append(args, "pillar="+string(pillarJSON))
	}

	output, err := execute.Run(ctx, execute.Options{
		Command: "salt",
		Args:    args,
		Capture: true,
	})

	if err != nil {
		logger.Error("Failed to apply state",
			zap.String("state", state),
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("applying state %s: %w", state, err)
	}

	logger.Info("State applied successfully",
		zap.String("state", state))

	return nil
}

// TestPing tests connectivity to Salt minions
func (c *Client) TestPing(ctx context.Context, target string) (bool, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Testing Salt connectivity",
		zap.String("target", target))

	output, err := execute.Run(ctx, execute.Options{
		Command: "salt",
		Args:    []string{target, "test.ping"},
		Capture: true,
	})

	if err != nil {
		return false, fmt.Errorf("ping test failed: %w", err)
	}

	return strings.Contains(output, "True"), nil
}

// GrainGet retrieves a grain value from minions
func (c *Client) GrainGet(ctx context.Context, target string, grain string) (map[string]interface{}, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Getting grain value",
		zap.String("target", target),
		zap.String("grain", grain))

	output, err := execute.Run(ctx, execute.Options{
		Command: "salt",
		Args:    []string{target, "grains.get", grain, "--output=json"},
		Capture: true,
	})

	if err != nil {
		return nil, fmt.Errorf("getting grain %s: %w", grain, err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return nil, fmt.Errorf("parsing grain output: %w", err)
	}

	return result, nil
}

// CmdRun executes a command on minions
func (c *Client) CmdRun(ctx context.Context, target string, command string) (string, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Running command via Salt",
		zap.String("target", target),
		zap.String("command", command))

	output, err := execute.Run(ctx, execute.Options{
		Command: "salt",
		Args:    []string{target, "cmd.run", command},
		Capture: true,
	})

	if err != nil {
		return "", fmt.Errorf("running command: %w", err)
	}

	return output, nil
}

// CheckMinion checks if a minion is available
func (c *Client) CheckMinion(ctx context.Context, minion string) (bool, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Checking minion status",
		zap.String("minion", minion))

	output, err := execute.Run(ctx, execute.Options{
		Command: "salt-run",
		Args:    []string{"manage.up"},
		Capture: true,
	})

	if err != nil {
		return false, fmt.Errorf("checking minion status: %w", err)
	}

	return strings.Contains(output, minion), nil
}

// StateApplyLocal applies a Salt state using salt-call (masterless mode)
func (c *Client) StateApplyLocal(ctx context.Context, state string, pillar map[string]interface{}) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Applying Salt state locally",
		zap.String("state", state))

	args := []string{"--local", "state.apply", state}

	if len(pillar) > 0 {
		pillarJSON, err := json.Marshal(pillar)
		if err != nil {
			return fmt.Errorf("marshaling pillar data: %w", err)
		}
		args = append(args, "pillar="+string(pillarJSON))
	}

	output, err := execute.Run(ctx, execute.Options{
		Command: "salt-call",
		Args:    args,
		Capture: true,
	})

	if err != nil {
		logger.Error("Failed to apply state locally",
			zap.String("state", state),
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("applying state %s locally: %w", state, err)
	}

	logger.Info("State applied successfully locally",
		zap.String("state", state))

	return nil
}

// CmdRunLocal runs a command locally using salt-call
func (c *Client) CmdRunLocal(ctx context.Context, command string) (string, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Running command locally via Salt",
		zap.String("command", command))

	output, err := execute.Run(ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "cmd.run", command},
		Capture: true,
	})

	if err != nil {
		return "", fmt.Errorf("running command locally: %w", err)
	}

	return output, nil
}

// Compatibility wrapper methods for existing code

// ApplyState is a wrapper for StateApply to maintain compatibility
func (c *Client) ApplyState(target, targetType, state string, pillar map[string]interface{}) error {
	// For the simplified client, we'll ignore targetType and always use ctx.Background()
	return c.StateApply(context.Background(), target, state, pillar)
}

// RunCommand is a wrapper for CmdRun to maintain compatibility
func (c *Client) RunCommand(target, targetType, function string, args []interface{}, kwargs map[string]interface{}) (string, error) {
	// For the simplified client, we'll only handle basic command execution
	if function == "cmd.run" && len(args) > 0 {
		if cmd, ok := args[0].(string); ok {
			return c.CmdRun(context.Background(), target, cmd)
		}
	}
	return "", fmt.Errorf("unsupported function: %s", function)
}

// GetGrains is a wrapper for GrainGet to maintain compatibility
func (c *Client) GetGrains(target, targetType string, grains []string) (map[string]interface{}, error) {
	// For the simplified client, get the first grain if available
	if len(grains) > 0 {
		return c.GrainGet(context.Background(), target, grains[0])
	}
	return make(map[string]interface{}), nil
}

// IsAPIAvailable performs comprehensive checks to determine if Salt API is available and working
func (c *Client) IsAPIAvailable(ctx context.Context) bool {
	logger := otelzap.Ctx(ctx)
	
	logger.Debug("Checking Salt API availability")
	
	// 1. Check if salt-api package is installed
	if !isPackageInstalled("salt-api") {
		logger.Debug("Salt API package not installed")
		return false
	}
	
	// 2. Check if salt-api service is running
	if !isServiceActive("salt-api") {
		logger.Debug("Salt API service not active")
		return false
	}
	
	// 3. Check if API configuration exists
	if !fileExists("/etc/salt/master.d/api.conf") {
		logger.Debug("Salt API configuration file not found")
		return false
	}
	
	// 4. Check if we can actually connect to the API
	if !canConnectToAPI(ctx) {
		logger.Debug("Cannot connect to Salt API")
		return false
	}
	
	logger.Debug("Salt API is available and working")
	return true
}

// isPackageInstalled checks if a package is installed using dpkg
func isPackageInstalled(packageName string) bool {
	cmd := exec.Command("dpkg", "-l", packageName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	// Check if package is installed (status starts with 'ii')
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ii") && strings.Contains(line, packageName) {
			return true
		}
	}
	return false
}

// isServiceActive checks if a systemd service is active
func isServiceActive(serviceName string) bool {
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	return strings.TrimSpace(string(output)) == "active"
}

// fileExists checks if a file exists
func fileExists(filepath string) bool {
	_, err := os.Stat(filepath)
	return err == nil
}

// canConnectToAPI attempts to connect to the Salt API
func canConnectToAPI(ctx context.Context) bool {
	// Try to make a simple API call to test connectivity
	// We'll use a basic health check endpoint or authentication endpoint
	
	// First, check if the API port is listening
	cmd := exec.CommandContext(ctx, "ss", "-tuln")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	// Look for common Salt API ports (8000, 8080)
	apiPorts := []string{":8000", ":8080"}
	for _, port := range apiPorts {
		if strings.Contains(string(output), port) {
			// Found a listening port, try to make a basic HTTP request
			return testAPIConnection(ctx, port)
		}
	}
	
	return false
}

// testAPIConnection tests if we can make a basic HTTP connection to the API
func testAPIConnection(ctx context.Context, port string) bool {
	// Extract port number from the format ":8000" 
	portNum := strings.TrimPrefix(port, ":")
	
	// Try to connect using curl to avoid complex HTTP client setup
	cmd := exec.CommandContext(ctx, "curl", "-s", "-k", "--connect-timeout", "2", 
		fmt.Sprintf("https://localhost:%s/", portNum))
	
	// We don't care about the response content, just that we can connect
	err := cmd.Run()
	return err == nil
}
