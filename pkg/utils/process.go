// pkg/utils/process.go

package utils

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GrepProcess returns a list of running processes matching the keyword (case-insensitive).
// DEPRECATED: Use pkg/eos_unix for process management operations
func GrepProcess(ctx context.Context, keyword string) (string, error) {
	logger := otelzap.Ctx(ctx)
	logger.Debug("🔍 Searching for processes", zap.String("keyword", keyword))

	// Use shell mode for piping - but this is inherently less secure
	// Better approach would be to use eos_unix package which has proper process handling
	command := fmt.Sprintf("ps aux | grep -i %q", keyword)

	output, err := execute.Run(ctx, execute.Options{
		Ctx:     ctx,
		Command: "sh",
		Args:    []string{"-c", command},
		Shell:   true, // Required for piping
		Capture: true,
	})

	if err != nil {
		logger.Error(" Failed to search processes",
			zap.String("keyword", keyword),
			zap.Error(err))
		return "", fmt.Errorf("process search failed: %w", err)
	}

	logger.Debug(" Process search completed",
		zap.String("keyword", keyword),
		zap.Int("output_length", len(output)))

	return output, nil
}
