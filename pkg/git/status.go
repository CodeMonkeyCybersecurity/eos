// Package git provides Git repository management utilities
package git

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetStatus retrieves the current Git repository status.
// It follows the Assess → Intervene → Evaluate pattern.
func GetStatus(rc *eos_io.RuntimeContext) (*GitStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Ensure git is available on this platform
	if !platform.IsCommandAvailable("git") {
		return nil, eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("git command not found - please install git"))
	}

	// INTERVENE - Get current branch
	branchOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "git",
		Args:    []string{"branch", "--show-current"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get current branch: %w", err)
	}

	// Get detailed status
	statusOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "git",
		Args:    []string{"status", "--porcelain"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get git status: %w", err)
	}

	// EVALUATE - Parse and build status
	status := &GitStatus{
		Branch:    strings.TrimSpace(branchOutput),
		IsClean:   strings.TrimSpace(statusOutput) == "",
		Staged:    []string{},
		Modified:  []string{},
		Untracked: []string{},
	}

	// Parse status lines
	scanner := bufio.NewScanner(strings.NewReader(statusOutput))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) < 3 {
			continue
		}

		statusCode := line[:2]
		filename := line[3:]

		switch {
		case strings.Contains(statusCode, "U") || strings.Contains(statusCode, "A"):
			status.HasConflicts = true
		case statusCode[0] != ' ' && statusCode[0] != '?':
			status.Staged = append(status.Staged, filename)
		case statusCode[1] != ' ':
			status.Modified = append(status.Modified, filename)
		case statusCode == "??":
			status.Untracked = append(status.Untracked, filename)
		}
	}

	logger.Debug("Git status retrieved",
		zap.String("branch", status.Branch),
		zap.Bool("is_clean", status.IsClean),
		zap.Int("staged", len(status.Staged)),
		zap.Int("modified", len(status.Modified)),
		zap.Int("untracked", len(status.Untracked)))

	return status, nil
}
