// Package git provides Git repository management utilities
package git

import (
	"bufio"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ShowCommitSummary displays a summary of the pending commit
func ShowCommitSummary(rc *eos_io.RuntimeContext, status *GitStatus, message string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Commit Summary")
	logger.Info("=================")
	logger.Info("Branch: " + status.Branch)

	if len(status.Staged) > 0 {
		logger.Info("Staged files:", zap.Strings("files", status.Staged))
	}
	if len(status.Modified) > 0 {
		logger.Info("Modified files:", zap.Strings("files", status.Modified))
	}
	if len(status.Untracked) > 0 {
		logger.Info("New files:", zap.Strings("files", status.Untracked))
	}

	logger.Info("\n📝 Commit Message:")
	logger.Info("===================")
	for _, line := range strings.Split(message, "\n") {
		logger.Info(line)
	}
	logger.Info("")

	return nil
}

// ConfirmCommit prompts the user for confirmation before committing
func ConfirmCommit(rc *eos_io.RuntimeContext) bool {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Do you want to proceed with this commit? (y/N): ")

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}
