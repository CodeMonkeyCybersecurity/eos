// pkg/execute/retry.go

package execute

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
)

// RetryCommand retries execution with live output and structured logging.
func RetryCommand(ctx context.Context, maxAttempts int, delay time.Duration, name string, args ...string) error {
	var lastErr error
	for i := 1; i <= maxAttempts; i++ {
		fmt.Printf("🔁 Attempt %d: %s %s\n", i, name, joinArgs(args))

		cmd := exec.CommandContext(ctx, name, args...)

		var buf bytes.Buffer
		cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
		cmd.Stderr = io.MultiWriter(os.Stderr, &buf)

		err := cmd.Run()
		if err == nil {
			fmt.Printf("✅ Attempt %d succeeded\n", i)
			return nil
		}

		output := buf.String()
		summary := eos_err.ExtractSummary(output, 2)
		lastErr = fmt.Errorf("❌ attempt %d failed: %w\noutput:\n%s", i, err, summary)

		if i < maxAttempts {
			time.Sleep(delay)
		}
	}
	return fmt.Errorf("❌ all %d attempts failed: %w", maxAttempts, lastErr)
}

// RetryCaptureOutput runs a command with retries and returns captured output.
func RetryCaptureOutput(ctx context.Context, retries int, delay time.Duration, name string, args ...string) ([]byte, error) {
	var out []byte
	var err error

	for i := 1; i <= retries; i++ {
		cmd := exec.CommandContext(ctx, name, args...)
		fmt.Printf("🔁 Capturing attempt %d: %s %s\n", i, name, joinArgs(args))
		out, err = cmd.CombinedOutput()

		if err == nil {
			return out, nil
		}

		fmt.Printf("❌ attempt %d failed: %s\n", i, err)
		if i < retries {
			time.Sleep(delay)
		}
	}

	return out, fmt.Errorf("all %d attempts failed: %w\noutput:\n%s", retries, err, string(out))
}
