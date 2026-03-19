package chatarchivecmd

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/chatarchive"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func BindFlags(cmd *cobra.Command) {
	cmd.Flags().StringSlice("source", chatarchive.DefaultSources(), "Source directories to scan")
	cmd.Flags().String("dest", chatarchive.DefaultDest(), "Destination archive directory")
	cmd.Flags().StringSlice("exclude", nil, "Path substrings to exclude from discovery (e.g. --exclude conversation-api)")
	cmd.Flags().Bool("dry-run", false, "Show what would be archived without copying files")
}

func Run(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	sources, _ := cmd.Flags().GetStringSlice("source")
	dest, _ := cmd.Flags().GetString("dest")
	excludes, _ := cmd.Flags().GetStringSlice("exclude")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	result, err := chatarchive.Archive(rc, chatarchive.Options{
		Sources:  sources,
		Dest:     dest,
		Excludes: excludes,
		DryRun:   dryRun,
	})
	if err != nil {
		return err
	}

	logger := otelzap.Ctx(rc.Ctx)
	writeSummary(cmd.OutOrStdout(), result, dryRun, logger)
	logger.Info("Chat archive summary",
		zap.Int("sources_requested", result.SourcesRequested),
		zap.Int("sources_scanned", result.SourcesScanned),
		zap.Int("sources_missing", len(result.MissingSources)),
		zap.Int("skipped_symlinks", result.SkippedSymlinks),
		zap.Int("unreadable_entries", result.UnreadableEntries),
		zap.Int("unique_files", result.UniqueFiles),
		zap.Int("duplicates", result.Duplicates),
		zap.Int("already_archived", result.Skipped),
		zap.Int("empty_files", result.EmptyFiles),
		zap.Int("failures", result.FailureCount),
		zap.Duration("duration", result.Duration),
		zap.Bool("dry_run", dryRun))
	for _, failure := range result.Failures {
		logger.Warn("Chat archive file failure",
			zap.String("path", failure.Path),
			zap.String("stage", failure.Stage),
			zap.String("reason", failure.Reason))
	}

	return nil
}

func formatSummary(result *chatarchive.Result, dryRun bool) string {
	lines := []string{
		statusLine(dryRun),
		fmt.Sprintf("Sources scanned: %d/%d", result.SourcesScanned, result.SourcesRequested),
		fmt.Sprintf("Unique files: %d", result.UniqueFiles),
		fmt.Sprintf("Duplicates in this run: %d", result.Duplicates),
		fmt.Sprintf("Already archived: %d", result.Skipped),
		fmt.Sprintf("Empty files ignored: %d", result.EmptyFiles),
		fmt.Sprintf("File failures: %d", result.FailureCount),
		fmt.Sprintf("Unreadable entries skipped: %d", result.UnreadableEntries),
		fmt.Sprintf("Symlinks skipped: %d", result.SkippedSymlinks),
		fmt.Sprintf("Duration: %s", result.Duration.Round(10*time.Millisecond)),
	}

	if result.ManifestPath != "" {
		lines = append(lines, fmt.Sprintf("Manifest: %s", result.ManifestPath))
	}
	if result.RecoveredManifestPath != "" {
		lines = append(lines, fmt.Sprintf("Recovered corrupt manifest: %s", result.RecoveredManifestPath))
	}
	if len(result.MissingSources) > 0 {
		lines = append(lines, fmt.Sprintf("Unavailable sources: %s", strings.Join(result.MissingSources, ", ")))
	}
	if result.FailureCount > len(result.Failures) {
		lines = append(lines, fmt.Sprintf("Additional failures not shown: %d", result.FailureCount-len(result.Failures)))
	}

	return strings.Join(lines, "\n")
}

func statusLine(dryRun bool) string {
	if dryRun {
		return "Dry run complete."
	}
	return "Archive complete."
}

func writeSummary(w io.Writer, result *chatarchive.Result, dryRun bool, logger otelzap.LoggerWithCtx) {
	if _, err := fmt.Fprintln(w, formatSummary(result, dryRun)); err != nil {
		logger.Warn("Failed to write chat archive summary", zap.Error(err))
	}
}
