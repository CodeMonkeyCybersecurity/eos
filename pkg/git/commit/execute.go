// Package commit provides Git commit functionality
package commit

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Execute performs a Git commit with the specified message.
// It follows the Assess → Intervene → Evaluate pattern.
func Execute(rc *eos_io.RuntimeContext, message string, noVerify bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Build command arguments
	args := []string{"commit", "-a", "-m", message}
	if noVerify {
		args = append(args, "--no-verify")
	}

	// INTERVENE - Execute commit
	logger.Info("Executing commit...")

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "git",
		Args:    args,
	})
	if err != nil {
		return fmt.Errorf("commit failed: %w\nOutput: %s", err, output)
	}

	// EVALUATE
	logger.Info("Commit successful", zap.String("output", output))
	return nil
}

// Push pushes the current branch to the remote repository.
// It follows the Assess → Intervene → Evaluate pattern.
func Push(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// INTERVENE - Execute push
	logger.Info("Pushing to remote...")

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "git",
		Args:    []string{"push"},
	})
	if err != nil {
		return fmt.Errorf("push failed: %w\nOutput: %s", err, output)
	}

	// EVALUATE
	logger.Info("Push successful", zap.String("output", output))
	return nil
}
