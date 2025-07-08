// package saltstack provides integration with Salt Stack for secure infrastructure management
package saltstack

import (
	"context"
	"encoding/json"
	"fmt"
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
		args = append(args, fmt.Sprintf("pillar='%s'", string(pillarJSON)))
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
