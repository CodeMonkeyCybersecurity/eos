package chatarchivecmd

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/chatarchive"
	"github.com/stretchr/testify/assert"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

func TestFormatSummaryIncludesDiscoveryTelemetry(t *testing.T) {
	t.Parallel()

	result := &chatarchive.Result{
		SourcesRequested:  3,
		SourcesScanned:    2,
		MissingSources:    []string{"/missing"},
		UnreadableEntries: 4,
		SkippedSymlinks:   5,
		UniqueFiles:       6,
		Duplicates:        1,
		Skipped:           2,
		EmptyFiles:        3,
		FailureCount:      0,
		Duration:          1250 * time.Millisecond,
		ManifestPath:      "/tmp/manifest.json",
	}

	summary := formatSummary(result, false)
	assert.Contains(t, summary, "Sources scanned: 2/3")
	assert.Contains(t, summary, "Unavailable sources: /missing")
	assert.Contains(t, summary, "Unreadable entries skipped: 4")
	assert.Contains(t, summary, "Symlinks skipped: 5")
	assert.Contains(t, summary, "Manifest: /tmp/manifest.json")
}

func TestWriteSummaryWritesToWriter(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writeSummary(&buf, &chatarchive.Result{SourcesRequested: 1, Duration: time.Second}, true, otelzap.Ctx(context.Background()))
	assert.Contains(t, buf.String(), "Dry run complete.")
}
