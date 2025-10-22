// pkg/debug/capture.go
// Automatic debug output capture to user's directory

package debug

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CaptureConfig holds configuration for debug output capture
type CaptureConfig struct {
	ServiceName string // e.g., "vault", "consul", "ceph"
	Output      string // The debug output to capture
	Format      string // "text", "json", "markdown"
}

// CaptureDebugOutput automatically saves debug output to user's directory
// This function is called by ALL debug commands automatically with no extra flags
func CaptureDebugOutput(rc *eos_io.RuntimeContext, config *CaptureConfig) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Determine user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to /tmp if can't get home dir
		logger.Warn("Could not determine user home directory, using /tmp",
			zap.Error(err))
		homeDir = "/tmp"
	}

	// Create .eos/debug directory in user's home
	debugDir := filepath.Join(homeDir, ".eos", "debug")
	if err := os.MkdirAll(debugDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create debug directory %s: %w", debugDir, err)
	}

	// Generate timestamped filename with metadata
	// Format: eos-debug-{service}-{timestamp}.{ext}
	// Example: eos-debug-vault-20251022-143052.txt
	timestamp := time.Now().Format("20060102-150405")
	extension := getExtension(config.Format)
	filename := fmt.Sprintf("eos-debug-%s-%s.%s", config.ServiceName, timestamp, extension)
	filepath := filepath.Join(debugDir, filename)

	// INTERVENE - Write debug output to file
	if err := os.WriteFile(filepath, []byte(config.Output), 0644); err != nil {
		return "", fmt.Errorf("failed to write debug output to %s: %w", filepath, err)
	}

	// EVALUATE - Log success with file location
	logger.Info("Debug output automatically saved",
		zap.String("service", config.ServiceName),
		zap.String("file", filepath),
		zap.String("size", formatBytes(len(config.Output))))

	return filepath, nil
}

// getExtension returns the appropriate file extension for the format
func getExtension(format string) string {
	switch format {
	case "json":
		return "json"
	case "markdown", "md":
		return "md"
	default: // "text" or anything else
		return "txt"
	}
}

// formatBytes formats byte count as human-readable string
func formatBytes(bytes int) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// CaptureStdoutFunc wraps a function that writes to stdout and captures its output
// This is useful for debug commands that print directly instead of returning output
// The captured output is automatically saved to ~/.eos/debug/
func CaptureStdoutFunc(rc *eos_io.RuntimeContext, serviceName string, fn func() error) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create a pipe to capture stdout
	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		logger.Warn("Failed to create pipe for stdout capture, running without capture", zap.Error(err))
		return fn() // Run without capture
	}

	// Replace stdout with our pipe writer
	os.Stdout = w

	// Buffer to capture output
	var buf bytes.Buffer
	done := make(chan error, 1)

	// Start copying from pipe to buffer in background
	go func() {
		_, copyErr := io.Copy(&buf, r)
		done <- copyErr
	}()

	// Run the function
	fnErr := fn()

	// Restore original stdout
	w.Close()
	os.Stdout = originalStdout

	// Wait for copy to finish
	<-done
	r.Close()

	// Get captured output
	output := buf.String()

	// If we captured anything, save it
	if len(output) > 0 {
		captureConfig := &CaptureConfig{
			ServiceName: serviceName,
			Output:      output,
			Format:      "text",
		}

		if _, captureErr := CaptureDebugOutput(rc, captureConfig); captureErr != nil {
			logger.Warn("Failed to auto-capture debug output", zap.Error(captureErr))
		}
	}

	// Return original function error
	return fnErr
}
