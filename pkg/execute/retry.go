// pkg/execute/retry.go
package execute

import (
	"fmt"
	"os/exec"
	"time"
)

// RetryCommand tries to run the given command up to maxAttempts.
func RetryCommand(maxAttempts int, delay time.Duration, cmd *exec.Cmd) error {
	var lastErr error
	for i := 1; i <= maxAttempts; i++ {
		fmt.Printf("🔁 Attempt %d: %s %v\n", i, cmd.Path, cmd.Args[1:])
		out, err := cmd.CombinedOutput()
		fmt.Print(string(out))

		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("attempt %d failed: %w\noutput: %s", i, err, string(out))
		time.Sleep(delay)
	}
	return fmt.Errorf("all %d attempts failed: %w", maxAttempts, lastErr)
}

func RetryCaptureOutput(retries int, delay time.Duration, cmd *exec.Cmd, out *[]byte) error {
	var err error
	for i := 0; i < retries; i++ {
		*out, err = cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		fmt.Printf("❌ Retry %d failed: %s\n", i+1, err)
		time.Sleep(delay)
	}
	return err
}
