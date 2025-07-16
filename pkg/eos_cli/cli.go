// pkg/eos_cli/cli.go

package eos_cli

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CLI provides a command execution interface for eos commands
type CLI struct {
	rc      *eos_io.RuntimeContext
	timeout time.Duration
}

// New creates a new CLI instance with the given runtime context
func New(rc *eos_io.RuntimeContext) *CLI {
	return &CLI{
		rc:      rc,
		timeout: 3 * time.Minute, // Default timeout
	}
}

// WithTimeout creates a new CLI instance with a custom timeout
func (c *CLI) WithTimeout(timeout time.Duration) *CLI {
	return &CLI{
		rc:      c.rc,
		timeout: timeout,
	}
}

// ExecString executes a command and returns its output as a string
func (c *CLI) ExecString(command string, args ...string) (string, error) {
	logger := otelzap.Ctx(c.rc.Ctx)
	
	logger.Debug("Executing command",
		zap.String("command", command),
		zap.Strings("args", args))
	
	ctx, cancel := context.WithTimeout(c.rc.Ctx, c.timeout)
	defer cancel()
	
	output, err := execute.Run(ctx, execute.Options{
		Command: command,
		Args:    args,
		Capture: true,
	})
	
	if err != nil {
		logger.Error("Command execution failed",
			zap.String("command", command),
			zap.Strings("args", args),
			zap.Error(err),
			zap.String("output", output))
		return "", fmt.Errorf("command %s failed: %w", command, err)
	}
	
	// Trim whitespace from output
	output = strings.TrimSpace(output)
	
	logger.Debug("Command executed successfully",
		zap.String("command", command),
		zap.String("output", output))
	
	return output, nil
}

// ExecToSuccess executes a command and returns an error if it fails
func (c *CLI) ExecToSuccess(command string, args ...string) error {
	logger := otelzap.Ctx(c.rc.Ctx)
	
	logger.Debug("Executing command to success",
		zap.String("command", command),
		zap.Strings("args", args))
	
	ctx, cancel := context.WithTimeout(c.rc.Ctx, c.timeout)
	defer cancel()
	
	output, err := execute.Run(ctx, execute.Options{
		Command: command,
		Args:    args,
		Capture: true,
	})
	
	if err != nil {
		logger.Error("Command execution failed",
			zap.String("command", command),
			zap.Strings("args", args),
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("command %s failed: %w", command, err)
	}
	
	logger.Debug("Command executed successfully",
		zap.String("command", command))
	
	return nil
}

// Which checks if a command exists in the system PATH
func (c *CLI) Which(command string) (string, error) {
	logger := otelzap.Ctx(c.rc.Ctx)
	
	logger.Debug("Checking for command existence",
		zap.String("command", command))
	
	path, err := exec.LookPath(command)
	if err != nil {
		logger.Debug("Command not found",
			zap.String("command", command),
			zap.Error(err))
		return "", fmt.Errorf("command %s not found in PATH: %w", command, err)
	}
	
	logger.Debug("Command found",
		zap.String("command", command),
		zap.String("path", path))
	
	return path, nil
}